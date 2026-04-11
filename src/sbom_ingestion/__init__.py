"""
sbom_ingestion — flexible SBOM ingestion bridge for unified-security-scanner.

Public API:
    - PackageModel, SBOMResult, SBOMFormat, SBOMSource  (format-agnostic contract)
    - CycloneDXParser, CycloneDXParseError             (CycloneDX 1.4/1.5 → PackageModel)
    - SBOMBridge, SBOMBridgeError                      (Detect → Reuse → Generate)
    - DepsDev                                          (package → repo slug enrichment)
    - VercelOnboarding, EntryPoint, ScanRequest,
      OnboardingStatus, create_scan_request            (3-entry-point onboarding)

Enrichment pipeline (OSV, EPSS, KEV, Scorecard) consumes PackageModel directly —
zero changes required when adding a new SBOM format.

See CLAUDE.md (Level 3) for ingestion priority order and enrichment rules.
"""

from __future__ import annotations

from .models import (
    PackageModel,
    SBOMFormat,
    SBOMResult,
    SBOMSource,
)
from .cyclonedx_parser import (
    CycloneDXParser,
    CycloneDXParseError,
)
from .sbom_bridge import (
    SBOMBridge,
    SBOMBridgeError,
)
from .deps_dev import DepsDev
from .vercel_onboarding import (
    EntryPoint,
    OnboardingStatus,
    ScanRequest,
    VercelOnboarding,
    create_scan_request,
)

__all__ = [
    # models
    "PackageModel",
    "SBOMFormat",
    "SBOMResult",
    "SBOMSource",
    # parsers
    "CycloneDXParser",
    "CycloneDXParseError",
    # bridge
    "SBOMBridge",
    "SBOMBridgeError",
    # enrichment
    "DepsDev",
    # onboarding
    "EntryPoint",
    "OnboardingStatus",
    "ScanRequest",
    "VercelOnboarding",
    "create_scan_request",
]

__version__ = "0.1.0"
