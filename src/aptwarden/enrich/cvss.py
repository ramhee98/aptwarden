"""CVSS scores for CVEs.

Primary: OSV's CVE-* records, which carry the CVSS vector (fast, no tight rate
limit). The CVSS 3.x base score is computed from the vector here. Fallback: the
NVD API 2.0 for CVEs without a v3 vector (e.g. v4 only). NVD is rate limited,
so it runs within a time budget per run. Remaining CVEs are retried on the next
run. Results, including "no score", are cached.
"""

from __future__ import annotations

import logging
import math
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from aptwarden.cache import Cache
from aptwarden.config import parse_duration, read_secret
from aptwarden.http import HttpClient, HttpError

log = logging.getLogger(__name__)

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}

NVD_INTERVAL_WITH_KEY = 0.7  # 50 requests / 30 s
NVD_INTERVAL_WITHOUT_KEY = 6.5  # 5 requests / 30 s

# state: "scored"  score known
#        "none"    no score anywhere yet (OSV carries NVD's data, so NVD has none either)
#        "nvd"     OSV has no v3 vector (v4 only, or no OSV record): waiting for NVD
_SCHEMA = """
CREATE TABLE IF NOT EXISTS cvss (
    cve TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    score REAL,
    version TEXT,
    vector TEXT,
    origin TEXT NOT NULL,
    fetched_at REAL NOT NULL
) WITHOUT ROWID;
"""


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: smallest number with one decimal >= value, robust
    against floating point noise (CVSS 3.1 spec, appendix A)."""
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float:
    """Base score for a CVSS:3.0 or CVSS:3.1 vector string."""
    parts = vector.strip().split("/")
    if not parts[0].startswith("CVSS:3."):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")
    try:
        m = dict(p.split(":", 1) for p in parts[1:])
        scope = m["S"]
        c, i, a = (_W["CIA"][m[k]] for k in ("C", "I", "A"))
        exploitability = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[scope][m["PR"]] \
            * _W["UI"][m["UI"]]
    except (KeyError, ValueError) as e:
        raise ValueError(f"invalid CVSS v3 vector: {vector!r}") from e
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    elif scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        raise ValueError(f"invalid CVSS v3 scope in {vector!r}")
    if impact <= 0:
        return 0.0
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(total, 10.0))


@dataclass
class CvssResult:
    score: float | None
    version: str | None
    vector: str | None
    origin: str  # "osv" or "nvd"


def parse_osv_severity(record: dict) -> CvssResult | None:
    """Score from an OSV record. None means "ask NVD" (no v3 vector)."""
    vectors = {s.get("type"): s.get("score", "") for s in record.get("severity", [])}
    v3 = vectors.get("CVSS_V3")
    if v3:
        try:
            return CvssResult(cvss3_base_score(v3), v3.split("/")[0][5:], v3, "osv")
        except ValueError:
            log.debug("bad cvss vector in osv record", extra={"vector": v3})
    return None


def parse_nvd(data: dict) -> CvssResult:
    """Pick the most useful metric from an NVD API 2.0 response."""
    vulns = data.get("vulnerabilities") or []
    metrics = vulns[0].get("cve", {}).get("metrics", {}) if vulns else {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
        for e in entries:
            d = e.get("cvssData", {})
            if d.get("baseScore") is not None:
                return CvssResult(float(d["baseScore"]), d.get("version"), d.get("vectorString"),
                                  "nvd")
    return CvssResult(None, None, None, "nvd")


class CvssLookup:
    def __init__(self, settings: dict, cache: Cache, http: HttpClient, offline: bool = False,
                 base_dir: Path | None = None):
        self.settings = settings
        self.cache = cache
        self.http = http
        self.offline = offline
        self.base_dir = base_dir
        self.cache.db.executescript(_SCHEMA)
        self.clock = time.monotonic
        self.sleep = time.sleep
        self.pending: int = 0  # CVEs left without an answer after the last lookup

    def lookup(self, cve_ids: list[str]) -> dict[str, CvssResult]:
        """Scores for ``cve_ids``, in priority order (NVD's budget is spent on
        the first ones). CVEs without a known score are absent."""
        wanted = [c for c in dict.fromkeys(cve_ids) if c.startswith("CVE-")]
        cached = self._cached(wanted)
        results = {c: r for c, (state, r) in cached.items() if state == "scored"}
        if self.offline:
            self.pending = sum(1 for c in wanted if c not in cached or cached[c][0] == "nvd")
            return results

        osv_todo = [c for c in wanted if c not in cached]
        new: dict[str, tuple[str, CvssResult]] = {}
        osv_failed = self._from_osv(osv_todo, new)

        nvd_settings = self.settings.get("nvd", {})
        nvd_todo = [c for c in wanted
                    if (cached.get(c) or new.get(c) or ("",))[0] == "nvd"]
        if nvd_todo and nvd_settings.get("enabled", True):
            self._from_nvd(nvd_todo, new, nvd_settings)

        now = time.time()
        with self.cache.db:
            self.cache.db.executemany(
                "INSERT OR REPLACE INTO cvss VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(c, st, r.score, r.version, r.vector, r.origin, now)
                 for c, (st, r) in new.items()],
            )
        results.update({c: r for c, (st, r) in new.items() if st == "scored"})
        nvd_enabled = nvd_settings.get("enabled", True)
        waiting = sum(1 for c in nvd_todo if new.get(c, ("nvd",))[0] == "nvd") if nvd_enabled else 0
        self.pending = waiting + osv_failed
        log.info("cvss lookup", extra={"wanted": len(wanted), "cached": len(cached),
                                       "osv_fetched": len(osv_todo), "nvd_waiting": waiting,
                                       "scored": len(results)})
        return results

    def _cached(self, cve_ids: list[str]) -> dict[str, tuple[str, CvssResult]]:
        ttl = parse_duration(self.settings.get("cache_ttl", "30d"))
        negative_ttl = parse_duration(self.settings.get("negative_ttl", "7d"))
        now = time.time()
        results = {}
        for cve in cve_ids:
            row = self.cache.db.execute(
                "SELECT state, score, version, vector, origin, fetched_at FROM cvss WHERE cve = ?",
                (cve,),
            ).fetchone()
            if not row:
                continue
            state, score, version, vector, origin, fetched_at = row
            # "nvd" stays valid until NVD answers; offline, stale data beats none.
            max_age = ttl if state == "scored" else negative_ttl
            if state == "nvd" or self.offline or now - fetched_at < max_age:
                results[cve] = (state, CvssResult(score, version, vector, origin))
        return results

    def _from_osv(self, todo: list[str], new: dict[str, tuple[str, CvssResult]]) -> int:
        """Look up OSV CVE records. Returns the number of failed requests."""
        if not todo:
            return 0
        url = self.settings.get("osv_url", "https://api.osv.dev").rstrip("/")

        def fetch(cve: str):
            try:
                resp = self.http.get(f"{url}/v1/vulns/{cve}", retries=1)
            except HttpError:
                return cve, None, None
            return cve, resp.status, resp.json() if resp.status == 200 else None

        failed = 0
        with ThreadPoolExecutor(max_workers=self.settings.get("workers", 8)) as pool:
            for cve, status, record in pool.map(fetch, todo):
                if status == 200:
                    result = parse_osv_severity(record)
                    if result is not None:
                        new[cve] = ("scored", result)
                    elif any(s.get("type") == "CVSS_V4" for s in record.get("severity", [])):
                        new[cve] = ("nvd", CvssResult(None, None, None, "osv"))
                    else:
                        new[cve] = ("none", CvssResult(None, None, None, "osv"))
                elif status == 404:
                    new[cve] = ("nvd", CvssResult(None, None, None, "osv"))
                else:
                    failed += 1  # retried next run
        return failed

    def _from_nvd(self, todo: list[str], new: dict[str, tuple[str, CvssResult]],
                  settings: dict) -> None:
        headers = {}
        if settings.get("api_key_file"):
            headers["apiKey"] = read_secret(settings["api_key_file"], self.base_dir)
        interval = NVD_INTERVAL_WITH_KEY if headers else NVD_INTERVAL_WITHOUT_KEY
        deadline = self.clock() + parse_duration(settings.get("budget", "2m"))
        url = settings.get("url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        last = None
        for cve in todo:
            wait = 0.0 if last is None else last + interval - self.clock()
            if self.clock() + max(wait, 0.0) >= deadline:
                break
            if wait > 0:
                self.sleep(wait)
            last = self.clock()
            try:
                resp = self.http.get(f"{url}?cveId={cve}", headers=headers, retries=0)
            except HttpError as e:
                log.warning("nvd request failed", extra={"cve": cve, "error": str(e)})
                break
            if resp.status in (403, 429, 503):
                log.warning("nvd rate limit hit, continuing next run",
                            extra={"status": resp.status})
                break
            if resp.status == 404:
                new[cve] = ("none", CvssResult(None, None, None, "nvd"))
            elif resp.status == 200:
                result = parse_nvd(resp.json())
                new[cve] = ("scored" if result.score is not None else "none", result)
