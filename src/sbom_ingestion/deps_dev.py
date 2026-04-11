"""
deps_dev.py — deps.dev package → source repo mapping adapter.

Ported from sbom-debt (APA production tool). Do not rewrite from scratch.

Purpose:
  OSSF Scorecard API requires a GitHub org/repo slug.
  Most PackageModel instances have a purl but no source_repo.
  This adapter resolves purl → GitHub repo via deps.dev.

API:
  GET https://api.deps.dev/v3alpha/purl/{purl}
  Returns: package metadata including sourceCode.url (GitHub URL)

Cache: 30-day TTL (per SAY-106 CLAUDE.md Level 3 enrichment rules)
Rate limits: No documented limit — be conservative, 10 req/s max.

Usage:
    resolver = DepsDev(cache_dir=Path("./cache"))
    repo = resolver.get_source_repo("pkg:npm/lodash@4.17.21")
    # → "lodash/lodash"
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

DEPS_DEV_BASE = "https://api.deps.dev/v3alpha"
CACHE_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days


class DepsDev:
    """
    Resolves package purl → GitHub source repo slug via deps.dev.

    Used by OSSF Scorecard adapter to convert PackageModel.purl
    into the org/repo string required by the Scorecard API.

    Maintains a local file cache at cache_dir/deps_dev/*.json
    with 30-day TTL to avoid redundant API calls.
    """

    def __init__(
        self,
        cache_dir: Path = Path("./cache"),
        rate_limit_rps: float = 10.0,
    ):
        self.cache_dir = Path(cache_dir) / "deps_dev"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._min_interval = 1.0 / rate_limit_rps
        self._last_request_time: float = 0.0

    def get_source_repo(self, purl: str) -> Optional[str]:
        """
        Resolve a purl to a GitHub org/repo slug.

        Returns:
            "owner/repo" string, or None if not resolvable.

        Never raises — returns None on any error so the caller
        can proceed without Scorecard enrichment for this package.
        """
        if not purl or not purl.startswith("pkg:"):
            return None

        # Check cache first
        cached = self._read_cache(purl)
        if cached is not None:
            return cached  # May be "" if previously resolved to None

        # Fetch from API
        try:
            repo = self._fetch_repo(purl)
        except Exception as e:
            logger.debug("deps.dev lookup failed for %s: %s", purl, e)
            repo = None

        # Cache result (including None → stored as "")
        self._write_cache(purl, repo or "")
        return repo

    def get_source_repos_batch(self, purls: list[str]) -> dict[str, Optional[str]]:
        """
        Resolve multiple purls. Returns dict of purl → repo_slug.
        Respects rate limiting between requests.
        """
        results: dict[str, Optional[str]] = {}
        for purl in purls:
            results[purl] = self.get_source_repo(purl)
        return results

    def enrich_packages(self, packages: list) -> list:
        """
        In-place enrich a list of PackageModel with source_repo via deps.dev.

        Only fetches for packages where source_repo is None and purl is set.
        Packages with existing source_repo are skipped (already resolved).
        """
        needs_lookup = [
            p for p in packages
            if p.purl and not p.source_repo
        ]

        if not needs_lookup:
            return packages

        logger.info(
            "deps.dev: resolving source repos for %d packages", len(needs_lookup)
        )

        purls = [p.purl for p in needs_lookup]
        resolved = self.get_source_repos_batch(purls)

        enriched = 0
        for pkg in needs_lookup:
            repo = resolved.get(pkg.purl)
            if repo:
                pkg.source_repo = repo
                enriched += 1

        logger.info(
            "deps.dev: resolved %d/%d source repos", enriched, len(needs_lookup)
        )
        return packages

    # ── API ────────────────────────────────────────────────────────────────

    def _fetch_repo(self, purl: str) -> Optional[str]:
        """Fetch package metadata from deps.dev and extract GitHub repo slug."""
        self._rate_limit()

        # URL-encode the purl for the path segment
        encoded_purl = quote(purl, safe="")
        url = f"{DEPS_DEV_BASE}/purl/{encoded_purl}"

        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 404:
                logger.debug("deps.dev: package not found: %s", purl)
                return None
            raise

        return self._extract_github_repo(data)

    def _extract_github_repo(self, data: dict) -> Optional[str]:
        """
        Extract GitHub org/repo from deps.dev response.

        deps.dev response structure (v3alpha):
        {
          "version": {
            "links": [
              {"label": "SOURCE_REPO", "url": "https://github.com/owner/repo"}
            ]
          }
        }
        """
        # Try version.links first (most reliable)
        version = data.get("version", {})
        for link in version.get("links", []):
            url = link.get("url", "")
            if "github.com/" in url:
                slug = _github_slug_from_url(url)
                if slug:
                    return slug

        # Fallback: package-level links
        package = data.get("package", {})
        for link in package.get("links", []):
            url = link.get("url", "")
            if "github.com/" in url:
                slug = _github_slug_from_url(url)
                if slug:
                    return slug

        # Fallback: sourceCode.url (older API format)
        source_code = data.get("sourceCode", {})
        url = source_code.get("url", "")
        if url and "github.com/" in url:
            return _github_slug_from_url(url)

        return None

    # ── Cache ──────────────────────────────────────────────────────────────

    def _cache_path(self, purl: str) -> Path:
        key = hashlib.sha256(purl.encode()).hexdigest()[:16]
        return self.cache_dir / f"{key}.json"

    def _read_cache(self, purl: str) -> Optional[str]:
        """
        Returns cached value if fresh, or None if missing/expired.
        Returns "" (empty string) if previously resolved to None.
        Returns the repo slug if previously resolved.
        """
        path = self._cache_path(purl)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            age = time.time() - entry.get("ts", 0)
            if age > CACHE_TTL_SECONDS:
                logger.debug("Cache expired for %s", purl)
                return None
            # Return stored value — "" means previously resolved to None
            return entry.get("repo", None)
        except Exception:
            return None

    def _write_cache(self, purl: str, repo: str) -> None:
        path = self._cache_path(purl)
        try:
            path.write_text(
                json.dumps({"purl": purl, "repo": repo, "ts": time.time()}),
                encoding="utf-8",
            )
        except OSError as e:
            logger.debug("Cache write failed for %s: %s", purl, e)

    def _rate_limit(self) -> None:
        """Enforce minimum interval between API requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_time = time.time()


# ── Helpers ────────────────────────────────────────────────────────────────

def _github_slug_from_url(url: str) -> Optional[str]:
    """Extract owner/repo from a GitHub URL. Strips .git suffix."""
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if prefix in url:
            after = url.split(prefix, 1)[1]
            parts = after.rstrip("/").split("/")[:2]
            if len(parts) == 2:
                return "/".join(parts).rstrip(".git").rstrip("/")
    return None
