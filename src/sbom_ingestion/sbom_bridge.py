"""
SBOMBridge — SBOM detection, routing, and generation.

Design principle: Detect → Reuse → Generate.
Never generate an SBOM when one already exists.

Priority order (resolve_sbom):
  1. Explicit file path provided → parse directly
  2. GitHub Dependency Graph API → fetch if enabled (free, no syft)
  3. Local SBOM discovery → glob standard filenames in repo root
  4. Fallback → generate via syft (last resort only)

Cache key: {repo_slug}_{git_sha} — skip generation if same commit already processed.

Integrates with:
  - CycloneDXParser (new — this module)
  - SPDXParser (existing sbom-debt parser — import, do not rewrite)
  - Enrichment pipeline (OSV, EPSS, KEV, Scorecard) — operates on PackageModel
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from .models import PackageModel, SBOMFormat, SBOMResult, SBOMSource
from .cyclonedx_parser import CycloneDXParser, CycloneDXParseError

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

GITHUB_API_BASE = "https://api.github.com"
SBOM_CACHE_DIR = Path("sbom_cache")

# Filenames discovered during local SBOM scan (priority order)
LOCAL_SBOM_GLOBS = [
    "sbom.spdx.json",
    "sbom.*.spdx.json",
    "*.spdx.json",
    "bom.json",
    "sbom.json",
    "sbom.cyclonedx.json",
    "sbom.*.cyclonedx.json",
    ".sbom/*.json",
    ".spdx/*.json",
]

# syft output format flags
SYFT_FORMAT_MAP = {
    SBOMFormat.SPDX_JSON: "spdx-json",
    SBOMFormat.CYCLONEDX_JSON: "cyclonedx-json",
}


class SBOMBridgeError(Exception):
    pass


class SBOMBridge:
    """
    Resolves SBOM input from any supported source into a list[PackageModel].

    Usage:
        bridge = SBOMBridge(github_token=os.environ.get("GITHUB_TOKEN"))
        result = bridge.resolve_sbom(
            source="https://github.com/GeeksikhSecurity/unified-security-scanner",
            format_preference=SBOMFormat.SPDX_JSON,
        )
        packages = result.packages  # list[PackageModel] — feed to enrichment
    """

    def __init__(
        self,
        github_token: Optional[str] = None,
        cache_dir: Path = SBOM_CACHE_DIR,
        syft_path: str = "syft",
    ):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.syft_path = syft_path
        self._cyclonedx_parser = CycloneDXParser()

    def resolve_sbom(
        self,
        source: str,
        format_preference: SBOMFormat = SBOMFormat.SPDX_JSON,
        git_sha: Optional[str] = None,
    ) -> SBOMResult:
        """
        Resolve SBOM from source using 4-step priority logic.

        Args:
            source:             File path, local directory, or GitHub repo URL
            format_preference:  SPDX_JSON (default) or CYCLONEDX_JSON for syft generation
            git_sha:            Commit SHA for cache keying (optional)

        Returns:
            SBOMResult with packages as list[PackageModel]
        """
        source = source.strip()

        # ── Step 1: Explicit file path ─────────────────────────────────────
        if self._is_file_path(source):
            logger.info("Step 1: Explicit SBOM file — %s", source)
            return self._parse_file(Path(source), SBOMSource.EXPLICIT_FILE)

        # ── Step 2: GitHub Dependency Graph API ───────────────────────────
        repo_slug = self._extract_github_slug(source)
        if repo_slug:
            cached = self._check_cache(repo_slug, git_sha)
            if cached:
                logger.info("Cache hit for %s@%s", repo_slug, git_sha)
                return cached

            logger.info("Step 2: Checking GitHub Dependency Graph for %s", repo_slug)
            github_result = self._fetch_github_sbom(repo_slug)
            if github_result:
                self._write_cache(github_result, repo_slug, git_sha)
                return github_result
            logger.info(
                "GitHub Dependency Graph not available for %s — continuing", repo_slug
            )

        # ── Step 3: Local SBOM discovery ──────────────────────────────────
        local_dir = Path(source) if Path(source).is_dir() else Path(".")
        logger.info("Step 3: Scanning for existing SBOM in %s", local_dir)
        local_result = self._discover_local_sbom(local_dir)
        if local_result:
            logger.info(
                "Found existing SBOM: %s (%s)",
                local_result.source_path, local_result.format.value,
            )
            return local_result

        # ── Step 4: Generate via syft ─────────────────────────────────────
        logger.info(
            "Step 4: No existing SBOM found — generating via syft (%s)",
            format_preference.value,
        )
        generated = self._generate_with_syft(source, format_preference, repo_slug, git_sha)
        if repo_slug and git_sha:
            self._write_cache(generated, repo_slug, git_sha)
        return generated

    # ── Parser routing ─────────────────────────────────────────────────────

    def _parse_file(
        self, path: Path, source: SBOMSource = SBOMSource.EXPLICIT_FILE
    ) -> SBOMResult:
        """Route file to correct parser based on format detection."""
        fmt = self._detect_format(path)
        logger.info("Detected format: %s for %s", fmt.value, path)

        if fmt == SBOMFormat.CYCLONEDX_JSON:
            result = self._cyclonedx_parser.parse_file(path)
            result.source = source
            return result

        if fmt == SBOMFormat.SPDX_JSON:
            return self._parse_spdx(path, source)

        # Unknown format — attempt CycloneDX first, then SPDX
        logger.warning("Unknown SBOM format for %s — attempting auto-detect", path)
        try:
            result = self._cyclonedx_parser.parse_file(path)
            result.source = source
            return result
        except CycloneDXParseError:
            pass
        return self._parse_spdx(path, source)

    def _parse_spdx(self, path: Path, source: SBOMSource) -> SBOMResult:
        """
        Parse SPDX 2.3 JSON using sbom-debt's existing parser.

        sbom-debt's SPDXParser is production-tested at APA (QUICKSTART.md).
        Import it here rather than reimplementing.

        If sbom-debt is not importable (standalone use), fall back to
        minimal SPDX extraction sufficient for PackageModel construction.
        """
        try:
            # Preferred: reuse sbom-debt's production parser
            from sbom_debt.parsing.spdx_parser import SPDXParser as SbomDebtSPDX
            logger.info("Using sbom-debt SPDXParser (production-tested)")
            raw = SbomDebtSPDX().parse(str(path))
            packages = [_sbom_debt_pkg_to_model(p) for p in raw.packages]
            return SBOMResult(
                packages=packages,
                format=SBOMFormat.SPDX_JSON,
                source=source,
                source_path=str(path),
                sbom_version=getattr(raw, "spdx_version", None),
                tool_name="sbom-debt/SPDXParser",
            )
        except ImportError:
            logger.info("sbom-debt not installed — using built-in SPDX parser")
            return self._parse_spdx_builtin(path, source)

    def _parse_spdx_builtin(self, path: Path, source: SBOMSource) -> SBOMResult:
        """
        Minimal built-in SPDX 2.3 JSON parser.
        Handles the common case: spdxVersion, packages[].{name,versionInfo,externalRefs}.
        """
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        spdx_version = data.get("spdxVersion", "")
        packages: list[PackageModel] = []

        for pkg in data.get("packages", []):
            name = pkg.get("name", "").strip()
            version = pkg.get("versionInfo", "").strip()
            if not name or not version or version == "NOASSERTION":
                continue

            purl = _extract_spdx_purl(pkg)
            source_repo = _extract_spdx_vcs(pkg)

            packages.append(PackageModel(
                name=name,
                version=version,
                purl=purl,
                source_repo=source_repo,
            ))

        logger.info("Built-in SPDX parser: %d packages from %s", len(packages), path)
        return SBOMResult(
            packages=packages,
            format=SBOMFormat.SPDX_JSON,
            source=source,
            source_path=str(path),
            sbom_version=spdx_version,
            tool_name="sbom-bridge/builtin-spdx",
        )

    # ── GitHub Dependency Graph ────────────────────────────────────────────

    def _fetch_github_sbom(self, repo_slug: str) -> Optional[SBOMResult]:
        """
        Fetch SBOM from GitHub Dependency Graph API.

        Returns None (not raises) if the repo has no Dependency Graph enabled.
        Callers must handle None as a signal to continue to the next step.

        API: GET /repos/{owner}/{repo}/dependency-graph/sbom
        Returns: CycloneDX 1.4 JSON wrapped in {"sbom": {...}}
        """
        url = f"{GITHUB_API_BASE}/repos/{repo_slug}/dependency-graph/sbom"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=15) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 404:
                logger.debug(
                    "GitHub Dependency Graph not enabled for %s (404)", repo_slug
                )
                return None
            if e.code == 403:
                logger.warning(
                    "GitHub API rate limited or insufficient scope for %s", repo_slug
                )
                return None
            logger.warning("GitHub API error %d for %s", e.code, repo_slug)
            return None
        except URLError as e:
            logger.warning("GitHub API unreachable: %s", e)
            return None

        # GitHub wraps the BOM in {"sbom": {...}}
        bom_data = raw.get("sbom", raw)
        result = self._cyclonedx_parser.parse_dict(
            bom_data,
            source_path=url,
            source=SBOMSource.GITHUB_API,
        )
        result.repo_slug = repo_slug
        logger.info(
            "GitHub Dependency Graph: %d packages for %s", result.package_count, repo_slug
        )
        return result

    # ── Local SBOM discovery ───────────────────────────────────────────────

    def _discover_local_sbom(self, directory: Path) -> Optional[SBOMResult]:
        """
        Scan directory for existing SBOM files using priority-ordered globs.
        Returns the first match, or None if no SBOM is found.
        """
        for pattern in LOCAL_SBOM_GLOBS:
            # Use rglob for patterns with subdirectory prefix, glob otherwise
            if "/" in pattern:
                matches = sorted(directory.glob(pattern))
            else:
                matches = sorted(directory.glob(pattern))
            for match in matches:
                if match.is_file() and match.stat().st_size > 0:
                    try:
                        result = self._parse_file(match, SBOMSource.LOCAL_DISCOVERY)
                        if result.package_count > 0:
                            return result
                        logger.debug("Empty SBOM at %s — skipping", match)
                    except Exception as e:
                        logger.debug("Could not parse %s: %s", match, e)
        return None

    # ── syft generation ────────────────────────────────────────────────────

    def _generate_with_syft(
        self,
        source: str,
        fmt: SBOMFormat,
        repo_slug: Optional[str],
        git_sha: Optional[str],
    ) -> SBOMResult:
        """
        Generate SBOM using syft as a subprocess.

        syft is invoked only when no existing SBOM is found (Step 4).
        Output written to sbom_cache/ with deterministic filename.
        """
        if not self._syft_available():
            raise SBOMBridgeError(
                "syft not found. Install from https://github.com/anchore/syft "
                "or provide an existing SBOM file."
            )

        syft_format = SYFT_FORMAT_MAP.get(fmt, "spdx-json")
        ext = "spdx.json" if fmt == SBOMFormat.SPDX_JSON else "cyclonedx.json"

        # Deterministic cache filename
        slug = repo_slug or _slugify(source)
        sha_suffix = f"_{git_sha[:8]}" if git_sha else ""
        output_path = self.cache_dir / f"{slug}{sha_suffix}.{ext}"

        cmd = [
            self.syft_path,
            source,
            "-o", f"{syft_format}={output_path}",
            "--quiet",
        ]
        logger.info("Running: %s", " ".join(str(c) for c in cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            raise SBOMBridgeError(f"syft timed out scanning {source}")
        except FileNotFoundError:
            raise SBOMBridgeError(f"syft executable not found at {self.syft_path!r}")

        if result.returncode != 0:
            raise SBOMBridgeError(
                f"syft exited {result.returncode}: {result.stderr.strip()}"
            )

        if not output_path.exists():
            raise SBOMBridgeError(f"syft did not produce output at {output_path}")

        logger.info("syft generated SBOM: %s", output_path)
        parsed = self._parse_file(output_path, SBOMSource.SYFT_GENERATED)
        parsed.repo_slug = repo_slug
        parsed.git_sha = git_sha
        return parsed

    # ── Cache ──────────────────────────────────────────────────────────────

    def _check_cache(
        self, repo_slug: str, git_sha: Optional[str]
    ) -> Optional[SBOMResult]:
        """Return cached SBOMResult if cache hit for repo_slug + git_sha."""
        if not git_sha:
            return None
        for ext in ("spdx.json", "cyclonedx.json"):
            path = self.cache_dir / f"{_slugify(repo_slug)}_{git_sha[:8]}.{ext}"
            if path.exists() and path.stat().st_size > 0:
                try:
                    result = self._parse_file(path, SBOMSource.LOCAL_DISCOVERY)
                    result.repo_slug = repo_slug
                    result.git_sha = git_sha
                    return result
                except Exception:
                    pass
        return None

    def _write_cache(
        self,
        result: SBOMResult,
        repo_slug: str,
        git_sha: Optional[str],
    ) -> None:
        """Write SBOMResult source file into cache if it came from GitHub API."""
        if result.source != SBOMSource.GITHUB_API or not git_sha:
            return
        # GitHub API results are parsed from an in-memory dict —
        # re-serialise the PackageModel list as a minimal JSON cache entry.
        cache_path = (
            self.cache_dir
            / f"{_slugify(repo_slug)}_{git_sha[:8]}.cache.json"
        )
        try:
            payload = {
                "repo_slug": repo_slug,
                "git_sha": git_sha,
                "format": result.format.value,
                "source": result.source.value,
                "packages": [
                    {
                        "name": p.name,
                        "version": p.version,
                        "purl": p.purl,
                        "ecosystem": p.ecosystem,
                        "source_repo": p.source_repo,
                        "license": p.license,
                    }
                    for p in result.packages
                ],
            }
            cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            logger.debug("Wrote GitHub SBOM cache: %s", cache_path)
        except OSError as e:
            logger.warning("Could not write cache: %s", e)

    # ── Utilities ──────────────────────────────────────────────────────────

    def _is_file_path(self, source: str) -> bool:
        """True if source looks like a local file (not a URL or directory scan)."""
        p = Path(source)
        return p.suffix in (".json", ".spdx") and p.exists()

    def _extract_github_slug(self, source: str) -> Optional[str]:
        """Extract owner/repo from a GitHub URL."""
        for prefix in (
            "https://github.com/",
            "http://github.com/",
            "github.com/",
        ):
            if source.startswith(prefix):
                slug = source[len(prefix):].rstrip("/").split("/")[:2]
                if len(slug) == 2:
                    return "/".join(slug)
        return None

    def _detect_format(self, path: Path) -> SBOMFormat:
        """
        Detect SPDX vs CycloneDX by reading the first few hundred bytes.
        Avoids loading the full file for format detection.
        """
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                head = f.read(512)
        except OSError:
            return SBOMFormat.UNKNOWN

        if '"spdxVersion"' in head or '"SPDX"' in head:
            return SBOMFormat.SPDX_JSON
        if '"bomFormat"' in head or '"CycloneDX"' in head or '"specVersion"' in head:
            return SBOMFormat.CYCLONEDX_JSON
        # Filename hints as tiebreaker
        name = path.name.lower()
        if "spdx" in name:
            return SBOMFormat.SPDX_JSON
        if "cyclonedx" in name or name == "bom.json":
            return SBOMFormat.CYCLONEDX_JSON
        return SBOMFormat.UNKNOWN

    def _syft_available(self) -> bool:
        """Check if syft is on PATH."""
        try:
            subprocess.run(
                [self.syft_path, "version"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False


# ── sbom-debt interop helpers ──────────────────────────────────────────────

def _sbom_debt_pkg_to_model(pkg: Any) -> PackageModel:
    """Convert sbom-debt Package dataclass → PackageModel."""
    return PackageModel(
        name=getattr(pkg, "name", ""),
        version=getattr(pkg, "version", ""),
        purl=getattr(pkg, "purl", None),
        ecosystem=getattr(pkg, "ecosystem", None),
        source_repo=getattr(pkg, "source_repo", None),
        license=getattr(pkg, "license", None),
    )


def _extract_spdx_purl(pkg: dict) -> Optional[str]:
    """Extract purl from SPDX package externalRefs."""
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceCategory") == "PACKAGE-MANAGER" and \
                ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def _extract_spdx_vcs(pkg: dict) -> Optional[str]:
    """Extract GitHub org/repo from SPDX package externalRefs."""
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceCategory") == "OTHER":
            locator = ref.get("referenceLocator", "")
            if "github.com/" in locator:
                parts = locator.split("github.com/")
                if len(parts) == 2:
                    slug = parts[1].rstrip(".git").split("/")[:2]
                    if len(slug) == 2:
                        return "/".join(slug)
    return None


def _slugify(text: str) -> str:
    """Convert arbitrary string to filesystem-safe slug."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in text)[:64]
