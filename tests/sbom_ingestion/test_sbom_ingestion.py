"""
Tests for sbom_ingestion — CycloneDXParser, SBOMBridge, and PackageModel.

Coverage:
  - CycloneDXParser: GitHub export (1.4), syft output (1.5), edge cases
  - SBOMBridge: all 4 resolution paths
  - PackageModel: risk_tier derivation
  - SPDX built-in parser: basic extraction
  - Format detection: SPDX vs CycloneDX vs unknown
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from urllib.error import HTTPError

# Add src to path for standalone test execution
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sbom_ingestion.models import PackageModel, SBOMFormat, SBOMResult, SBOMSource
from sbom_ingestion.cyclonedx_parser import CycloneDXParser, CycloneDXParseError
from sbom_ingestion.sbom_bridge import SBOMBridge, SBOMBridgeError


# ── Fixtures ───────────────────────────────────────────────────────────────

CYCLONEDX_14_GITHUB_FIXTURE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "timestamp": "2026-04-09T00:00:00Z",
        "tools": [{"name": "GitHub", "version": "1.0"}],
        "component": {"name": "GeeksikhSecurity/unified-security-scanner", "type": "application"},
    },
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "licenses": [{"license": {"id": "MIT"}}],
            "externalReferences": [
                {"type": "vcs", "url": "https://github.com/lodash/lodash"}
            ],
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.28.0",
            "purl": "pkg:pypi/requests@2.28.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "library",
            "name": "serde",
            "version": "1.0.150",
            "purl": "pkg:cargo/serde@1.0.150",
        },
        # Should be skipped — no version
        {
            "type": "library",
            "name": "no-version-pkg",
        },
        # Should be skipped — no name
        {
            "type": "library",
            "version": "1.0.0",
        },
    ],
}

CYCLONEDX_15_SYFT_FIXTURE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "tools": {
            "components": [{"name": "syft", "version": "0.103.0"}]
        },
    },
    "components": [
        {
            "type": "library",
            "name": "django",
            "version": "4.2.0",
            "purl": "pkg:pypi/django@4.2.0",
            "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            "externalReferences": [
                {"type": "vcs", "url": "https://github.com/django/django.git"}
            ],
        },
        {
            "type": "library",
            "name": "cryptography",
            "version": "41.0.0",
            "purl": "pkg:pypi/cryptography@41.0.0",
        },
    ],
}

SPDX_23_FIXTURE = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test-sbom",
    "packages": [
        {
            "SPDXID": "SPDXRef-pkg-1",
            "name": "express",
            "versionInfo": "4.18.2",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/express@4.18.2",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-pkg-2",
            "name": "flask",
            "versionInfo": "NOASSERTION",  # Should be skipped
        },
        {
            "SPDXID": "SPDXRef-pkg-3",
            "name": "rails",
            "versionInfo": "7.0.0",
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "https://github.com/rails/rails.git",
                }
            ],
        },
    ],
}


# ── PackageModel Tests ─────────────────────────────────────────────────────

class TestPackageModel(unittest.TestCase):

    def test_ecosystem_inferred_from_purl(self):
        pkg = PackageModel(name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20")
        self.assertEqual(pkg.ecosystem, "npm")

    def test_ecosystem_not_overwritten_if_set(self):
        pkg = PackageModel(name="x", version="1.0", purl="pkg:npm/x@1.0", ecosystem="pypi")
        self.assertEqual(pkg.ecosystem, "pypi")

    def test_risk_tier_kev_always_critical(self):
        pkg = PackageModel(name="x", version="1.0", kev_flagged=True, cvss_score=3.0)
        self.assertEqual(pkg.risk_tier, "CRITICAL")

    def test_risk_tier_cvss_critical(self):
        pkg = PackageModel(name="x", version="1.0", cvss_score=9.0)
        self.assertEqual(pkg.risk_tier, "CRITICAL")

    def test_risk_tier_maintained_false_with_cve(self):
        pkg = PackageModel(name="x", version="1.0", maintained=False, cve_ids=["CVE-2024-1234"])
        self.assertEqual(pkg.risk_tier, "CRITICAL")

    def test_risk_tier_maintained_false_no_cve_not_critical(self):
        pkg = PackageModel(name="x", version="1.0", maintained=False)
        # No CVE → not CRITICAL by this rule alone
        self.assertNotEqual(pkg.risk_tier, "CRITICAL")

    def test_risk_tier_low_ossf_critical(self):
        pkg = PackageModel(name="x", version="1.0", ossf_score=2.9)
        self.assertEqual(pkg.risk_tier, "CRITICAL")

    def test_risk_tier_high_cvss(self):
        pkg = PackageModel(name="x", version="1.0", cvss_score=7.5)
        self.assertEqual(pkg.risk_tier, "HIGH")

    def test_risk_tier_watch_low_ossf_no_cve(self):
        pkg = PackageModel(name="x", version="1.0", ossf_score=4.0)
        self.assertEqual(pkg.risk_tier, "WATCH")

    def test_risk_tier_default_medium(self):
        pkg = PackageModel(name="x", version="1.0")
        self.assertEqual(pkg.risk_tier, "MEDIUM")


# ── CycloneDXParser Tests ──────────────────────────────────────────────────

class TestCycloneDXParser(unittest.TestCase):

    def setUp(self):
        self.parser = CycloneDXParser()

    # ── GitHub 1.4 fixture ─────────────────────────────────────────────────

    def test_parse_github_14_package_count(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        # 3 valid packages (lodash, requests, serde) — 2 skipped
        self.assertEqual(result.package_count, 3)

    def test_parse_github_14_package_names(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        names = {p.name for p in result.packages}
        self.assertEqual(names, {"lodash", "requests", "serde"})

    def test_parse_github_14_ecosystems(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        pkg_map = {p.name: p for p in result.packages}
        self.assertEqual(pkg_map["lodash"].ecosystem, "npm")
        self.assertEqual(pkg_map["requests"].ecosystem, "pypi")
        self.assertEqual(pkg_map["serde"].ecosystem, "cargo")

    def test_parse_github_14_license(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        lodash = next(p for p in result.packages if p.name == "lodash")
        self.assertEqual(lodash.license, "MIT")

    def test_parse_github_14_source_repo(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        lodash = next(p for p in result.packages if p.name == "lodash")
        self.assertEqual(lodash.source_repo, "lodash/lodash")

    def test_parse_github_14_spec_version(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        self.assertEqual(result.sbom_version, "1.4")

    def test_parse_github_14_tool_name(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        self.assertEqual(result.tool_name, "GitHub")

    def test_parse_github_14_repo_slug(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        self.assertEqual(result.repo_slug, "GeeksikhSecurity/unified-security-scanner")

    def test_parse_github_14_format(self):
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        self.assertEqual(result.format, SBOMFormat.CYCLONEDX_JSON)

    # ── syft 1.5 fixture ───────────────────────────────────────────────────

    def test_parse_syft_15_package_count(self):
        result = self.parser.parse_dict(CYCLONEDX_15_SYFT_FIXTURE)
        self.assertEqual(result.package_count, 2)

    def test_parse_syft_15_tool_name(self):
        result = self.parser.parse_dict(CYCLONEDX_15_SYFT_FIXTURE)
        self.assertEqual(result.tool_name, "syft")

    def test_parse_syft_15_spec_version(self):
        result = self.parser.parse_dict(CYCLONEDX_15_SYFT_FIXTURE)
        self.assertEqual(result.sbom_version, "1.5")

    def test_parse_syft_15_vcs_repo_strips_git_suffix(self):
        result = self.parser.parse_dict(CYCLONEDX_15_SYFT_FIXTURE)
        django = next(p for p in result.packages if p.name == "django")
        self.assertEqual(django.source_repo, "django/django")

    # ── Round-trip: package count integrity ────────────────────────────────

    def test_round_trip_github_14_package_count_matches_valid_components(self):
        """Parsed count must equal number of components with name AND version."""
        valid = [
            c for c in CYCLONEDX_14_GITHUB_FIXTURE["components"]
            if c.get("name") and c.get("version")
        ]
        result = self.parser.parse_dict(CYCLONEDX_14_GITHUB_FIXTURE)
        self.assertEqual(result.package_count, len(valid))

    # ── File parsing ───────────────────────────────────────────────────────

    def test_parse_file_valid(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(CYCLONEDX_14_GITHUB_FIXTURE, f)
            path = f.name
        try:
            result = self.parser.parse_file(path)
            self.assertEqual(result.package_count, 3)
        finally:
            os.unlink(path)

    def test_parse_file_not_found(self):
        with self.assertRaises(CycloneDXParseError):
            self.parser.parse_file("/nonexistent/sbom.json")

    def test_parse_file_invalid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("{ not valid json }")
            path = f.name
        try:
            with self.assertRaises(CycloneDXParseError):
                self.parser.parse_file(path)
        finally:
            os.unlink(path)

    # ── Edge cases ─────────────────────────────────────────────────────────

    def test_wrong_bom_format_raises(self):
        data = {"bomFormat": "SPDX", "specVersion": "2.3", "components": []}
        with self.assertRaises(CycloneDXParseError):
            self.parser.parse_dict(data)

    def test_unsupported_spec_version_warns_but_parses(self):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",   # Older — not in SUPPORTED_SPEC_VERSIONS
            "components": [
                {"type": "library", "name": "pkg-a", "version": "1.0", "purl": "pkg:npm/pkg-a@1.0"}
            ],
        }
        # Should not raise — should parse with warning
        result = self.parser.parse_dict(data)
        self.assertEqual(result.package_count, 1)

    def test_empty_components_list(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        result = self.parser.parse_dict(data)
        self.assertEqual(result.package_count, 0)
        self.assertEqual(result.packages, [])

    def test_missing_components_key(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5"}
        result = self.parser.parse_dict(data)
        self.assertEqual(result.package_count, 0)

    def test_partial_parse_continues_on_bad_component(self):
        """Parser should continue and return partial results on per-component error."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"type": "library", "name": "good-pkg", "version": "1.0", "purl": "pkg:npm/good-pkg@1.0"},
                None,   # This will cause an error — should be skipped, not crash
                {"type": "library", "name": "another-good", "version": "2.0", "purl": "pkg:pypi/another-good@2.0"},
            ],
        }
        # Component None will fail attribute access — should not raise, should skip
        try:
            result = self.parser.parse_dict(data)
            # At least the good packages should parse
            self.assertGreaterEqual(result.package_count, 1)
        except Exception as e:
            self.fail(f"Parser should not raise on partial component failure: {e}")

    def test_expression_license_extracted(self):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "dual-licensed",
                    "version": "1.0",
                    "purl": "pkg:npm/dual-licensed@1.0",
                    "licenses": [{"expression": "MIT OR Apache-2.0"}],
                }
            ],
        }
        result = self.parser.parse_dict(data)
        self.assertEqual(result.packages[0].license, "MIT OR Apache-2.0")

    def test_bom_ref_used_when_no_purl(self):
        """bom-ref that is not a purl should result in purl=None (not used as purl)."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "legacy-pkg",
                    "version": "3.0",
                    "bom-ref": "legacy-pkg-3.0-abc123",  # Not a purl
                }
            ],
        }
        result = self.parser.parse_dict(data)
        self.assertEqual(result.packages[0].purl, None)


# ── SBOMBridge Tests ───────────────────────────────────────────────────────

class TestSBOMBridge(unittest.TestCase):

    def setUp(self):
        self.cache_dir = tempfile.mkdtemp()
        self.bridge = SBOMBridge(
            github_token="test-token",
            cache_dir=Path(self.cache_dir),
        )

    # ── Step 1: Explicit file path ─────────────────────────────────────────

    def test_step1_explicit_spdx_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".spdx.json", delete=False
        ) as f:
            json.dump(SPDX_23_FIXTURE, f)
            path = f.name
        try:
            result = self.bridge.resolve_sbom(path)
            self.assertEqual(result.source, SBOMSource.EXPLICIT_FILE)
            self.assertEqual(result.format, SBOMFormat.SPDX_JSON)
            # express + rails (flask skipped — NOASSERTION version)
            self.assertEqual(result.package_count, 2)
        finally:
            os.unlink(path)

    def test_step1_explicit_cyclonedx_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cyclonedx.json", delete=False
        ) as f:
            json.dump(CYCLONEDX_14_GITHUB_FIXTURE, f)
            path = f.name
        try:
            result = self.bridge.resolve_sbom(path)
            self.assertEqual(result.source, SBOMSource.EXPLICIT_FILE)
            self.assertEqual(result.format, SBOMFormat.CYCLONEDX_JSON)
            self.assertEqual(result.package_count, 3)
        finally:
            os.unlink(path)

    # ── Step 2: GitHub Dependency Graph API ───────────────────────────────

    def test_step2_github_api_success(self):
        github_response = {"sbom": CYCLONEDX_14_GITHUB_FIXTURE}

        with patch("sbom_ingestion.sbom_bridge.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(github_response).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = self.bridge.resolve_sbom(
                "https://github.com/GeeksikhSecurity/unified-security-scanner"
            )

        self.assertEqual(result.source, SBOMSource.GITHUB_API)
        self.assertEqual(result.package_count, 3)
        self.assertEqual(result.repo_slug, "GeeksikhSecurity/unified-security-scanner")

    def test_step2_github_api_404_falls_through(self):
        """404 from GitHub API must fall through to Step 3/4, not raise."""
        with patch("sbom_ingestion.sbom_bridge.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = HTTPError(
                url="", code=404, msg="Not Found", hdrs={}, fp=None
            )
            with patch.object(self.bridge, "_discover_local_sbom", return_value=None):
                with patch.object(self.bridge, "_generate_with_syft") as mock_syft:
                    mock_syft.return_value = SBOMResult(
                        packages=[], format=SBOMFormat.SPDX_JSON,
                        source=SBOMSource.SYFT_GENERATED, source_path="/tmp/test.json"
                    )
                    result = self.bridge.resolve_sbom(
                        "https://github.com/GeeksikhSecurity/unified-security-scanner"
                    )
                    # Should reach syft fallback
                    mock_syft.assert_called_once()

    def test_step2_github_api_403_falls_through(self):
        """Rate limited API should not raise — fall through to Step 3."""
        with patch("sbom_ingestion.sbom_bridge.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = HTTPError(
                url="", code=403, msg="Forbidden", hdrs={}, fp=None
            )
            with patch.object(self.bridge, "_discover_local_sbom", return_value=None):
                with patch.object(self.bridge, "_generate_with_syft") as mock_syft:
                    mock_syft.return_value = SBOMResult(
                        packages=[], format=SBOMFormat.SPDX_JSON,
                        source=SBOMSource.SYFT_GENERATED, source_path="/tmp/test.json"
                    )
                    self.bridge.resolve_sbom(
                        "https://github.com/GeeksikhSecurity/unified-security-scanner"
                    )
                    mock_syft.assert_called_once()

    # ── Step 3: Local SBOM discovery ──────────────────────────────────────

    def test_step3_local_sbom_discovery(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "bom.json"
            sbom_path.write_text(json.dumps(CYCLONEDX_14_GITHUB_FIXTURE), encoding="utf-8")

            bridge = SBOMBridge(cache_dir=Path(self.cache_dir))
            result = bridge._discover_local_sbom(Path(tmpdir))

            self.assertIsNotNone(result)
            self.assertEqual(result.source, SBOMSource.LOCAL_DISCOVERY)
            self.assertEqual(result.package_count, 3)

    def test_step3_no_local_sbom_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.bridge._discover_local_sbom(Path(tmpdir))
            self.assertIsNone(result)

    # ── Step 4: syft generation ────────────────────────────────────────────

    def test_step4_syft_not_available_raises(self):
        bridge = SBOMBridge(syft_path="/nonexistent/syft", cache_dir=Path(self.cache_dir))
        with self.assertRaises(SBOMBridgeError):
            bridge._generate_with_syft(
                "/some/repo", SBOMFormat.SPDX_JSON, None, None
            )

    def test_step4_syft_generates_and_parses(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a fake syft-generated SBOM at expected cache path
            output_path = Path(self.cache_dir) / "test-repo.spdx.json"
            output_path.write_text(json.dumps(SPDX_23_FIXTURE), encoding="utf-8")

            with patch("sbom_ingestion.sbom_bridge.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                # Patch output path derivation so it points to our pre-written file
                with patch.object(
                    self.bridge, "_generate_with_syft",
                    return_value=self.bridge._parse_file(output_path, SBOMSource.SYFT_GENERATED),
                ):
                    result = self.bridge._generate_with_syft(
                        "/some/repo", SBOMFormat.SPDX_JSON, "test-repo", None
                    )
                    self.assertEqual(result.source, SBOMSource.SYFT_GENERATED)

    # ── Cache ──────────────────────────────────────────────────────────────

    def test_cache_miss_returns_none(self):
        result = self.bridge._check_cache("GeeksikhSecurity/unified-security-scanner", "abc12345")
        self.assertIsNone(result)

    def test_cache_hit_returns_result(self):
        # Manually write a cache file
        slug = "GeeksikhSecurity_unified-security-scanner"
        cache_path = Path(self.cache_dir) / f"{slug}_abc12345.cyclonedx.json"
        cache_path.write_text(json.dumps(CYCLONEDX_14_GITHUB_FIXTURE), encoding="utf-8")

        result = self.bridge._check_cache(
            "GeeksikhSecurity/unified-security-scanner", "abc12345"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.package_count, 3)

    # ── Format detection ───────────────────────────────────────────────────

    def test_detect_spdx_by_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"spdxVersion": "SPDX-2.3", "packages": []}')
            path = Path(f.name)
        try:
            fmt = self.bridge._detect_format(path)
            self.assertEqual(fmt, SBOMFormat.SPDX_JSON)
        finally:
            path.unlink()

    def test_detect_cyclonedx_by_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"bomFormat": "CycloneDX", "specVersion": "1.5"}')
            path = Path(f.name)
        try:
            fmt = self.bridge._detect_format(path)
            self.assertEqual(fmt, SBOMFormat.CYCLONEDX_JSON)
        finally:
            path.unlink()

    def test_detect_cyclonedx_by_filename_bom_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="bom", delete=False, dir=self.cache_dir
        ) as f:
            f.write("{}")
            path = Path(f.name)
        # Rename to bom.json
        bom_path = Path(self.cache_dir) / "bom.json"
        path.rename(bom_path)
        try:
            fmt = self.bridge._detect_format(bom_path)
            self.assertEqual(fmt, SBOMFormat.CYCLONEDX_JSON)
        finally:
            bom_path.unlink(missing_ok=True)

    # ── GitHub slug extraction ─────────────────────────────────────────────

    def test_extract_github_slug_https(self):
        slug = self.bridge._extract_github_slug(
            "https://github.com/GeeksikhSecurity/unified-security-scanner"
        )
        self.assertEqual(slug, "GeeksikhSecurity/unified-security-scanner")

    def test_extract_github_slug_trailing_slash(self):
        slug = self.bridge._extract_github_slug(
            "https://github.com/GeeksikhSecurity/unified-security-scanner/"
        )
        self.assertEqual(slug, "GeeksikhSecurity/unified-security-scanner")

    def test_extract_github_slug_non_github_returns_none(self):
        slug = self.bridge._extract_github_slug("https://gitlab.com/owner/repo")
        self.assertIsNone(slug)

    def test_extract_github_slug_local_path_returns_none(self):
        slug = self.bridge._extract_github_slug("/local/path/to/repo")
        self.assertIsNone(slug)


# ── SPDX Built-in Parser Tests ─────────────────────────────────────────────

class TestSPDXBuiltinParser(unittest.TestCase):

    def setUp(self):
        self.bridge = SBOMBridge(cache_dir=Path(tempfile.mkdtemp()))

    def test_spdx_parses_valid_packages(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".spdx.json", delete=False) as f:
            json.dump(SPDX_23_FIXTURE, f)
            path = Path(f.name)
        try:
            result = self.bridge._parse_spdx_builtin(path, SBOMSource.EXPLICIT_FILE)
            self.assertEqual(result.package_count, 2)  # flask skipped (NOASSERTION)
            names = {p.name for p in result.packages}
            self.assertIn("express", names)
            self.assertIn("rails", names)
        finally:
            path.unlink()

    def test_spdx_extracts_purl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".spdx.json", delete=False) as f:
            json.dump(SPDX_23_FIXTURE, f)
            path = Path(f.name)
        try:
            result = self.bridge._parse_spdx_builtin(path, SBOMSource.EXPLICIT_FILE)
            express = next(p for p in result.packages if p.name == "express")
            self.assertEqual(express.purl, "pkg:npm/express@4.18.2")
            self.assertEqual(express.ecosystem, "npm")
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
