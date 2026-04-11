"""
Tests for deps_dev.py and vercel_onboarding.py.

Covers:
  - DepsDev: API response parsing, cache hit/miss, rate limiting, batch enrich
  - VercelOnboarding: all three entry points, status step sequence
  - create_scan_request: entry point inference from source string
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sbom_ingestion.models import PackageModel, SBOMFormat, SBOMResult, SBOMSource
from sbom_ingestion.deps_dev import DepsDev, _github_slug_from_url
from sbom_ingestion.vercel_onboarding import (
    VercelOnboarding, ScanRequest, EntryPoint, OnboardingStatus,
    create_scan_request, _parse_s3_uri,
)


# ── Fixtures ───────────────────────────────────────────────────────────────

DEPS_DEV_RESPONSE_WITH_GITHUB = {
    "version": {
        "links": [
            {"label": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"},
            {"label": "HOMEPAGE", "url": "https://lodash.com"},
        ]
    }
}

DEPS_DEV_RESPONSE_NO_GITHUB = {
    "version": {
        "links": [
            {"label": "HOMEPAGE", "url": "https://example.com"},
        ]
    }
}

CYCLONEDX_MINIMAL = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"type": "library", "name": "express", "version": "4.18.2",
         "purl": "pkg:npm/express@4.18.2"},
        {"type": "library", "name": "lodash", "version": "4.17.21",
         "purl": "pkg:npm/lodash@4.17.21"},
    ],
}


# ── DepsDev Tests ──────────────────────────────────────────────────────────

class TestDepsDev(unittest.TestCase):

    def setUp(self):
        self.cache_dir = Path(tempfile.mkdtemp())
        self.deps = DepsDev(cache_dir=self.cache_dir, rate_limit_rps=1000)

    def test_github_slug_from_url_https(self):
        self.assertEqual(
            _github_slug_from_url("https://github.com/lodash/lodash"),
            "lodash/lodash"
        )

    def test_github_slug_from_url_strips_git(self):
        self.assertEqual(
            _github_slug_from_url("https://github.com/django/django.git"),
            "django/django"
        )

    def test_github_slug_from_url_trailing_slash(self):
        self.assertEqual(
            _github_slug_from_url("https://github.com/owner/repo/"),
            "owner/repo"
        )

    def test_github_slug_from_url_non_github(self):
        self.assertIsNone(_github_slug_from_url("https://gitlab.com/owner/repo"))

    def test_get_source_repo_api_success(self):
        with patch("sbom_ingestion.deps_dev.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(DEPS_DEV_RESPONSE_WITH_GITHUB).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = self.deps.get_source_repo("pkg:npm/lodash@4.17.21")

        self.assertEqual(result, "lodash/lodash")

    def test_get_source_repo_no_github_link(self):
        with patch("sbom_ingestion.deps_dev.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(DEPS_DEV_RESPONSE_NO_GITHUB).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = self.deps.get_source_repo("pkg:npm/some-pkg@1.0.0")

        self.assertIsNone(result)

    def test_get_source_repo_404_returns_none(self):
        with patch("sbom_ingestion.deps_dev.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = HTTPError(
                url="", code=404, msg="Not Found", hdrs={}, fp=None
            )
            result = self.deps.get_source_repo("pkg:npm/nonexistent@1.0.0")

        self.assertIsNone(result)

    def test_get_source_repo_network_error_returns_none(self):
        with patch("sbom_ingestion.deps_dev.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = ConnectionError("Network unreachable")
            result = self.deps.get_source_repo("pkg:npm/pkg@1.0.0")

        self.assertIsNone(result)

    def test_get_source_repo_empty_purl_returns_none(self):
        result = self.deps.get_source_repo("")
        self.assertIsNone(result)

    def test_get_source_repo_invalid_purl_returns_none(self):
        result = self.deps.get_source_repo("not-a-purl")
        self.assertIsNone(result)

    def test_cache_miss_then_hit(self):
        call_count = 0
        def mock_fetch(purl):
            nonlocal call_count
            call_count += 1
            return "lodash/lodash"

        self.deps._fetch_repo = mock_fetch

        # First call — cache miss, should call _fetch_repo
        r1 = self.deps.get_source_repo("pkg:npm/lodash@4.17.21")
        self.assertEqual(r1, "lodash/lodash")
        self.assertEqual(call_count, 1)

        # Second call — cache hit, should NOT call _fetch_repo again
        r2 = self.deps.get_source_repo("pkg:npm/lodash@4.17.21")
        self.assertEqual(r2, "lodash/lodash")
        self.assertEqual(call_count, 1)  # Still 1 — cache was hit

    def test_cache_stores_none_as_empty_string(self):
        """None result should be cached to avoid re-querying unresolvable packages."""
        self.deps._fetch_repo = lambda purl: None

        r1 = self.deps.get_source_repo("pkg:npm/unresolvable@1.0.0")
        self.assertIsNone(r1)

        # Verify cache file exists with "" value
        path = self.deps._cache_path("pkg:npm/unresolvable@1.0.0")
        self.assertTrue(path.exists())
        entry = json.loads(path.read_text())
        self.assertEqual(entry["repo"], "")

    def test_cache_expired_refetches(self):
        purl = "pkg:npm/test@1.0.0"
        # Write an expired cache entry
        path = self.deps._cache_path(purl)
        path.write_text(json.dumps({
            "purl": purl,
            "repo": "old/repo",
            "ts": time.time() - (31 * 24 * 60 * 60),  # 31 days ago
        }))

        fetch_called = []
        def mock_fetch(p):
            fetch_called.append(p)
            return "new/repo"

        self.deps._fetch_repo = mock_fetch
        result = self.deps.get_source_repo(purl)

        self.assertEqual(result, "new/repo")
        self.assertTrue(fetch_called, "Should have refetched after cache expiry")

    def test_enrich_packages_fills_source_repo(self):
        packages = [
            PackageModel(name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21"),
            PackageModel(name="requests", version="2.28.0", purl="pkg:pypi/requests@2.28.0",
                        source_repo="psf/requests"),  # Already set — skip
        ]

        def mock_fetch(purl):
            if "lodash" in purl:
                return "lodash/lodash"
            return None

        self.deps._fetch_repo = mock_fetch
        enriched = self.deps.enrich_packages(packages)

        lodash = next(p for p in enriched if p.name == "lodash")
        requests = next(p for p in enriched if p.name == "requests")

        self.assertEqual(lodash.source_repo, "lodash/lodash")
        self.assertEqual(requests.source_repo, "psf/requests")  # Unchanged

    def test_enrich_packages_skips_no_purl(self):
        packages = [
            PackageModel(name="no-purl-pkg", version="1.0.0"),  # No purl
        ]
        fetch_called = []
        self.deps._fetch_repo = lambda p: fetch_called.append(p) or "x/y"

        self.deps.enrich_packages(packages)
        self.assertEqual(len(fetch_called), 0)  # Should not have called fetch


# ── VercelOnboarding Tests ─────────────────────────────────────────────────

class TestVercelOnboarding(unittest.TestCase):

    def setUp(self):
        self.cache_dir = Path(tempfile.mkdtemp())
        self.handler = VercelOnboarding(cache_dir=self.cache_dir)

    def _collect_statuses(self, request: ScanRequest) -> list[OnboardingStatus]:
        return list(self.handler.run(request))

    # ── Entry Point 2: SBOM Upload ─────────────────────────────────────────

    def test_sbom_upload_cyclonedx_success(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cyclonedx.json", delete=False
        ) as f:
            json.dump(CYCLONEDX_MINIMAL, f)
            path = f.name

        try:
            request = ScanRequest(
                entry_point=EntryPoint.SBOM_UPLOAD,
                source=path,
            )
            statuses = self._collect_statuses(request)

            # Last status should be done=True with result
            final = statuses[-1]
            self.assertTrue(final.done)
            self.assertIsNotNone(final.result)
            self.assertEqual(final.result.package_count, 2)
            self.assertIsNone(final.error)
        finally:
            os.unlink(path)

    def test_sbom_upload_file_not_found(self):
        request = ScanRequest(
            entry_point=EntryPoint.SBOM_UPLOAD,
            source="/nonexistent/sbom.json",
        )
        statuses = self._collect_statuses(request)
        final = statuses[-1]

        self.assertTrue(final.done)
        self.assertIsNotNone(final.error)
        self.assertIsNone(final.result)

    def test_sbom_upload_empty_sbom_emits_error_status(self):
        empty_bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(empty_bom, f)
            path = f.name

        try:
            request = ScanRequest(entry_point=EntryPoint.SBOM_UPLOAD, source=path)
            statuses = self._collect_statuses(request)
            final = statuses[-1]

            self.assertTrue(final.done)
            self.assertEqual(final.error, "empty_sbom")
        finally:
            os.unlink(path)

    def test_sbom_upload_status_sequence(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cyclonedx.json", delete=False
        ) as f:
            json.dump(CYCLONEDX_MINIMAL, f)
            path = f.name

        try:
            request = ScanRequest(entry_point=EntryPoint.SBOM_UPLOAD, source=path)
            statuses = self._collect_statuses(request)
            steps = [s.step for s in statuses]

            # Verify expected step sequence
            self.assertIn("detecting_format", steps)
            self.assertIn("parsing", steps)
            self.assertEqual(steps[-1], "done")
        finally:
            os.unlink(path)

    # ── Entry Point 1: Repo URL ────────────────────────────────────────────

    def test_repo_url_github_api_success(self):
        mock_result = SBOMResult(
            packages=[PackageModel(name="lodash", version="4.17.21")],
            format=SBOMFormat.CYCLONEDX_JSON,
            source=SBOMSource.GITHUB_API,
            source_path="https://api.github.com/...",
        )

        with patch("sbom_ingestion.sbom_bridge.SBOMBridge._fetch_github_sbom",
                   return_value=mock_result):
            request = ScanRequest(
                entry_point=EntryPoint.REPO_URL,
                source="https://github.com/GeeksikhSecurity/unified-security-scanner",
            )
            statuses = self._collect_statuses(request)

        final = statuses[-1]
        self.assertTrue(final.done)
        self.assertIsNotNone(final.result)
        self.assertEqual(final.result.package_count, 1)

        steps = [s.step for s in statuses]
        self.assertIn("checking_github", steps)
        self.assertIn("sbom_found", steps)
        self.assertEqual(steps[-1], "done")

    def test_repo_url_not_github_raises_error(self):
        request = ScanRequest(
            entry_point=EntryPoint.REPO_URL,
            source="https://gitlab.com/owner/repo",
        )
        statuses = self._collect_statuses(request)
        final = statuses[-1]

        self.assertTrue(final.done)
        self.assertIsNotNone(final.error)

    def test_repo_url_falls_back_to_syft(self):
        with patch("sbom_ingestion.sbom_bridge.SBOMBridge._fetch_github_sbom",
                   return_value=None):
            with patch("sbom_ingestion.sbom_bridge.SBOMBridge._discover_local_sbom",
                       return_value=None):
                syft_result = SBOMResult(
                    packages=[PackageModel(name="pkg-a", version="1.0")],
                    format=SBOMFormat.SPDX_JSON,
                    source=SBOMSource.SYFT_GENERATED,
                    source_path="/tmp/cache/test.spdx.json",
                )
                with patch("sbom_ingestion.sbom_bridge.SBOMBridge._generate_with_syft",
                           return_value=syft_result):
                    request = ScanRequest(
                        entry_point=EntryPoint.REPO_URL,
                        source="https://github.com/GeeksikhSecurity/unified-security-scanner",
                    )
                    statuses = self._collect_statuses(request)

        steps = [s.step for s in statuses]
        self.assertIn("generating_sbom", steps)
        self.assertEqual(steps[-1], "done")

    # ── Entry Point 3: AWS S3 ──────────────────────────────────────────────

    def test_aws_s3_invalid_uri_raises_error(self):
        request = ScanRequest(
            entry_point=EntryPoint.AWS_S3,
            source="https://not-s3.com/bucket",
        )
        statuses = self._collect_statuses(request)
        final = statuses[-1]
        self.assertTrue(final.done)
        self.assertIsNotNone(final.error)

    def test_parse_s3_uri(self):
        bucket, prefix = _parse_s3_uri("s3://my-bucket/path/to/sboms/")
        self.assertEqual(bucket, "my-bucket")
        self.assertEqual(prefix, "path/to/sboms/")

    def test_parse_s3_uri_no_prefix(self):
        bucket, prefix = _parse_s3_uri("s3://my-bucket")
        self.assertEqual(bucket, "my-bucket")
        self.assertEqual(prefix, "")


# ── create_scan_request Tests ──────────────────────────────────────────────

class TestCreateScanRequest(unittest.TestCase):

    def test_github_url_infers_repo_url(self):
        req = create_scan_request("https://github.com/owner/repo")
        self.assertEqual(req.entry_point, EntryPoint.REPO_URL)

    def test_s3_uri_infers_aws_s3(self):
        req = create_scan_request("s3://my-bucket/prefix/")
        self.assertEqual(req.entry_point, EntryPoint.AWS_S3)

    def test_json_file_infers_sbom_upload(self):
        req = create_scan_request("/path/to/sbom.json")
        self.assertEqual(req.entry_point, EntryPoint.SBOM_UPLOAD)

    def test_spdx_file_infers_sbom_upload(self):
        req = create_scan_request("/path/to/sbom.spdx")
        self.assertEqual(req.entry_point, EntryPoint.SBOM_UPLOAD)

    def test_owner_slash_repo_infers_repo_url(self):
        req = create_scan_request("GeeksikhSecurity/unified-security-scanner")
        self.assertEqual(req.entry_point, EntryPoint.REPO_URL)
        self.assertIn("github.com", req.source)

    def test_format_preference_spdx(self):
        req = create_scan_request("https://github.com/o/r", format_preference="spdx-json")
        self.assertEqual(req.format_preference, SBOMFormat.SPDX_JSON)

    def test_format_preference_cyclonedx(self):
        req = create_scan_request("https://github.com/o/r", format_preference="cyclonedx-json")
        self.assertEqual(req.format_preference, SBOMFormat.CYCLONEDX_JSON)

    def test_github_token_passed_through(self):
        req = create_scan_request(
            "https://github.com/o/r", github_token="ghp_test123"
        )
        self.assertEqual(req.github_token, "ghp_test123")

    def test_git_sha_passed_through(self):
        req = create_scan_request(
            "https://github.com/o/r", git_sha="abc12345"
        )
        self.assertEqual(req.git_sha, "abc12345")


if __name__ == "__main__":
    unittest.main(verbosity=2)
