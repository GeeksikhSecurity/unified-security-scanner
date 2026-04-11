"""
CycloneDXParser — parses CycloneDX 1.4 and 1.5 JSON into PackageModel.

This is the single new file required to add CycloneDX support.
No changes to OSVAdapter, ScorecardAdapter, scoring, or dashboard.

Supported sources:
  - GitHub Dependency Graph export (CycloneDX 1.4)
  - syft-generated output (CycloneDX 1.5)
  - Any CycloneDX 1.4/1.5 JSON conforming to the spec

Schema reference:
  https://cyclonedx.org/docs/1.5/json/
  https://cyclonedx.org/docs/1.4/json/
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from .models import PackageModel, SBOMFormat, SBOMResult, SBOMSource

logger = logging.getLogger(__name__)

# Supported spec versions
SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5"}


class CycloneDXParseError(Exception):
    pass


class CycloneDXParser:
    """
    Parses CycloneDX 1.4/1.5 JSON → list[PackageModel].

    Design contract:
      - Input:  CycloneDX JSON (dict or file path)
      - Output: SBOMResult with packages as list[PackageModel]
      - Never raises on individual package failures — logs and continues
      - Caller receives partial results rather than a full parse failure
    """

    def parse_file(self, path: str | Path) -> SBOMResult:
        """Parse a CycloneDX JSON file from disk."""
        path = Path(path)
        if not path.exists():
            raise CycloneDXParseError(f"SBOM file not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise CycloneDXParseError(f"Invalid JSON in {path}: {e}") from e
        return self.parse_dict(data, source_path=str(path))

    def parse_dict(
        self,
        data: dict[str, Any],
        source_path: str = "<dict>",
        source: SBOMSource = SBOMSource.EXPLICIT_FILE,
    ) -> SBOMResult:
        """Parse a CycloneDX JSON dict (already loaded)."""
        self._validate_schema(data)

        spec_version = data.get("specVersion", "unknown")
        metadata = data.get("metadata", {})
        tool_name = self._extract_tool_name(metadata)
        repo_slug = self._extract_repo_slug(metadata, data)

        components = data.get("components", [])
        packages: list[PackageModel] = []
        skipped = 0

        for i, component in enumerate(components):
            try:
                pkg = self._parse_component(component)
                if pkg:
                    packages.append(pkg)
            except Exception as e:
                skipped += 1
                cname = (
                    component.get("name", "<unnamed>")
                    if isinstance(component, dict)
                    else f"<{type(component).__name__}>"
                )
                logger.warning(
                    "Skipped component[%d] in %s: %s — %s",
                    i, source_path, cname, e
                )

        if skipped:
            logger.warning(
                "Parsed %d/%d components from %s (%d skipped)",
                len(packages), len(components), source_path, skipped,
            )
        else:
            logger.info(
                "Parsed %d components from %s (CycloneDX %s)",
                len(packages), source_path, spec_version,
            )

        return SBOMResult(
            packages=packages,
            format=SBOMFormat.CYCLONEDX_JSON,
            source=source,
            source_path=source_path,
            sbom_version=spec_version,
            tool_name=tool_name,
            repo_slug=repo_slug,
        )

    # ── Private helpers ────────────────────────────────────────────────────

    def _validate_schema(self, data: dict[str, Any]) -> None:
        """Validate minimal required CycloneDX structure."""
        if not isinstance(data, dict):
            raise CycloneDXParseError("Expected JSON object at root")

        # bomFormat is required in CycloneDX spec
        bom_format = data.get("bomFormat", "")
        if bom_format and bom_format != "CycloneDX":
            raise CycloneDXParseError(
                f"Not a CycloneDX BOM — bomFormat: {bom_format!r}"
            )

        spec_version = data.get("specVersion", "")
        if spec_version and spec_version not in SUPPORTED_SPEC_VERSIONS:
            logger.warning(
                "CycloneDX specVersion %r not explicitly tested — "
                "attempting parse anyway", spec_version
            )

    def _parse_component(self, component: dict[str, Any]) -> Optional[PackageModel]:
        """
        Map a CycloneDX component to PackageModel.

        CycloneDX component fields used:
          - name (required)
          - version (required for enrichment — skip if absent)
          - purl (preferred identifier)
          - bom-ref (fallback identifier)
          - licenses[].license.id
          - description
          - externalReferences[].url (type=vcs → source_repo)
        """
        name = component.get("name", "").strip()
        if not name:
            logger.debug("Skipping anonymous component: %s", component)
            return None

        version = (component.get("version") or "").strip()
        if not version:
            logger.debug(
                "Skipping %s — no version (cannot enrich without version)", name
            )
            return None

        purl = component.get("purl") or component.get("bom-ref") or None
        # Normalise bom-ref: if it's not a purl scheme, treat as opaque ID only
        if purl and not purl.startswith("pkg:"):
            purl = None

        ecosystem = _ecosystem_from_component(component, purl)
        license_id = _extract_license(component)
        source_repo = _extract_vcs_repo(component)
        description = component.get("description")

        return PackageModel(
            name=name,
            version=version,
            purl=purl,
            ecosystem=ecosystem,
            source_repo=source_repo,
            license=license_id,
            description=description,
        )

    def _extract_tool_name(self, metadata: dict[str, Any]) -> Optional[str]:
        """Extract generating tool name from metadata.tools."""
        tools = metadata.get("tools", {})
        # CycloneDX 1.5: tools is object with components[] and services[]
        if isinstance(tools, dict):
            components = tools.get("components", [])
            if components:
                return components[0].get("name")
        # CycloneDX 1.4: tools is array
        if isinstance(tools, list) and tools:
            return tools[0].get("name")
        return None

    def _extract_repo_slug(
        self, metadata: dict[str, Any], data: dict[str, Any]
    ) -> Optional[str]:
        """
        Extract repo slug (owner/repo) from metadata.component or
        metadata.properties for GitHub SBOM exports.
        """
        # GitHub export embeds repo in metadata.component.name
        component = metadata.get("component", {})
        if component:
            name = component.get("name", "")
            # GitHub format: "owner/repo"
            if "/" in name and not name.startswith("pkg:"):
                return name

        # Check metadata.properties for com.github.* keys
        for prop in metadata.get("properties", []):
            if prop.get("name") == "com.github.package.metadata.repo":
                return prop.get("value")

        return None


# ── Module-level helpers ───────────────────────────────────────────────────

def _ecosystem_from_component(
    component: dict[str, Any], purl: Optional[str]
) -> Optional[str]:
    """Infer ecosystem from purl, component type, or component properties."""
    # Preferred: extract from purl
    if purl and purl.startswith("pkg:"):
        try:
            return purl.split("/")[0].replace("pkg:", "").lower()
        except IndexError:
            pass

    # CycloneDX component type hint
    comp_type = component.get("type", "")
    type_map = {
        "container": "container",
        "device": None,
        "firmware": None,
    }
    if comp_type in type_map:
        return type_map[comp_type]

    # Check properties for ecosystem hint (some generators add this)
    for prop in component.get("properties", []):
        if prop.get("name", "").lower() in ("ecosystem", "package-manager"):
            return prop.get("value", "").lower() or None

    return None


def _extract_license(component: dict[str, Any]) -> Optional[str]:
    """Extract first SPDX license ID from component.licenses."""
    licenses = component.get("licenses", [])
    for entry in licenses:
        # CycloneDX 1.4/1.5: {"license": {"id": "MIT"}} or {"license": {"name": "..."}}
        lic = entry.get("license", {})
        spdx_id = lic.get("id") or lic.get("name")
        if spdx_id:
            return spdx_id
        # expression form: {"expression": "MIT OR Apache-2.0"}
        expr = entry.get("expression")
        if expr:
            return expr
    return None


def _extract_vcs_repo(component: dict[str, Any]) -> Optional[str]:
    """Extract GitHub org/repo from externalReferences of type 'vcs'."""
    for ref in component.get("externalReferences", []):
        if ref.get("type") == "vcs":
            url = ref.get("url", "")
            # https://github.com/owner/repo → owner/repo
            if "github.com/" in url:
                parts = url.rstrip("/").split("github.com/")
                if len(parts) == 2:
                    slug = parts[1].rstrip(".git")
                    if "/" in slug:
                        return slug
    return None
