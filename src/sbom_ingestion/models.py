"""
Shared data models for SBOM ingestion.

Both SPDX and CycloneDX parsers output to PackageModel.
Enrichment pipeline (OSV, EPSS, KEV, Scorecard) is format-agnostic after parsing.
No enrichment code changes are needed when adding new SBOM formats.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SBOMFormat(str, Enum):
    SPDX_JSON = "spdx-json"
    CYCLONEDX_JSON = "cyclonedx-json"
    UNKNOWN = "unknown"


class SBOMSource(str, Enum):
    EXPLICIT_FILE = "explicit_file"       # User-provided path
    GITHUB_API = "github_api"             # GitHub Dependency Graph export
    LOCAL_DISCOVERY = "local_discovery"   # Found in repo root
    SYFT_GENERATED = "syft_generated"     # Generated as fallback


@dataclass
class PackageModel:
    """
    Canonical package representation consumed by the enrichment pipeline.

    All SBOM parsers (SPDX, CycloneDX) must output this model.
    Enrichment adapters (OSV, EPSS, KEV, Scorecard) operate only on this type.
    """
    name: str
    version: str
    purl: Optional[str] = None          # Package URL (pkg:npm/lodash@4.17.21)
    ecosystem: Optional[str] = None     # npm | pypi | cargo | maven | go | rubygems
    source_repo: Optional[str] = None   # GitHub org/repo for Scorecard lookup
    license: Optional[str] = None
    description: Optional[str] = None
    # Populated by enrichment pipeline — not by parsers
    cve_ids: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_flagged: bool = False
    ossf_score: Optional[float] = None
    maintained: Optional[bool] = None   # OSSF Scorecard Maintained check
    fix_version: Optional[str] = None

    def __post_init__(self):
        # Infer ecosystem from purl if not explicitly set
        if self.purl and not self.ecosystem:
            self.ecosystem = _ecosystem_from_purl(self.purl)

    @property
    def risk_tier(self) -> str:
        """Derived risk tier per SAY-106 enrichment rules."""
        if self.kev_flagged:
            return "CRITICAL"
        if self.cvss_score and self.cvss_score >= 9.0:
            return "CRITICAL"
        if self.maintained is False and self.cve_ids:
            return "CRITICAL"
        if self.ossf_score is not None and self.ossf_score < 3:
            return "CRITICAL"
        if self.cvss_score and self.cvss_score >= 7.0:
            return "HIGH"
        if self.ossf_score is not None and self.ossf_score < 5:
            return "WATCH"
        return "MEDIUM"


@dataclass
class SBOMResult:
    """Output of SBOMBridge.resolve_sbom() — carries packages and provenance."""
    packages: list[PackageModel]
    format: SBOMFormat
    source: SBOMSource
    source_path: str                     # File path or URL used
    package_count: int = 0
    sbom_version: Optional[str] = None
    tool_name: Optional[str] = None      # Generating tool (syft, GitHub, etc.)
    repo_slug: Optional[str] = None
    git_sha: Optional[str] = None

    def __post_init__(self):
        self.package_count = len(self.packages)


def _ecosystem_from_purl(purl: str) -> Optional[str]:
    """Extract ecosystem from Package URL scheme."""
    # pkg:npm/lodash@4.17.21 → npm
    # pkg:pypi/requests@2.28.0 → pypi
    try:
        scheme = purl.split("/")[0].replace("pkg:", "")
        return scheme.lower() if scheme else None
    except (IndexError, AttributeError):
        return None
