"""
vercel_onboarding.py — Three-entry-point SBOM ingestion for Vercel marketplace.

Entry points:
  1. Repo URL scan      → check GitHub Dependency Graph → fallback syft → enrich
  2. SBOM file upload   → detect format → parse → enrich
  3. AWS S3 bucket      → download SPDX 2.3 exports → enrich (sbom-debt pipeline)

Design goals (from SAY-106 CLAUDE.md):
  - "Checking for existing SBOM..." status before syft fallback (UX transparency)
  - CycloneDX and SPDX both accepted on upload — format sniffed from content
  - AWS S3 entry reuses sbom-debt S3 storage backend directly

Used by:
  - Vercel marketplace API route: POST /api/scan/init
  - CLI entry point: sbom-debt run --source <url|file|s3>
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .models import SBOMFormat, SBOMResult, SBOMSource
from .sbom_bridge import SBOMBridge, SBOMBridgeError

logger = logging.getLogger(__name__)


class EntryPoint(str, Enum):
    REPO_URL = "repo_url"       # GitHub repo URL → check Dep Graph → syft fallback
    SBOM_UPLOAD = "sbom_upload" # User-provided SPDX or CycloneDX file
    AWS_S3 = "aws_s3"           # S3 bucket with AWS Inspector SPDX exports


@dataclass
class ScanRequest:
    """Validated input to the onboarding handler."""
    entry_point: EntryPoint
    source: str                          # URL, file path, or S3 URI
    format_preference: SBOMFormat = SBOMFormat.SPDX_JSON
    git_sha: Optional[str] = None
    aws_profile: Optional[str] = None
    github_token: Optional[str] = None


@dataclass
class OnboardingStatus:
    """
    Progressive status for UI rendering during scan init.
    The Vercel marketplace shows these as step indicators.
    """
    step: str           # Current step label
    detail: str         # Human-readable detail
    done: bool = False
    error: Optional[str] = None
    result: Optional[SBOMResult] = None


class VercelOnboarding:
    """
    Handles the three-entry-point onboarding flow for the Vercel marketplace.

    Yields OnboardingStatus objects for progressive UI updates.
    The caller iterates these to update the status display before the
    enrichment pipeline runs.

    Usage (API route):
        handler = VercelOnboarding(cache_dir=Path("/tmp/sbom_cache"))
        for status in handler.run(request):
            emit_sse(status)   # Server-sent event to client
        result = status.result
    """

    def __init__(
        self,
        cache_dir: Path = Path("/tmp/sbom_cache"),
        syft_path: str = "syft",
    ):
        self.cache_dir = Path(cache_dir)

    def run(self, request: ScanRequest):
        """
        Generator — yields OnboardingStatus at each step.
        Final yield has done=True and result set.
        """
        try:
            yield from self._dispatch(request)
        except SBOMBridgeError as e:
            yield OnboardingStatus(
                step="error",
                detail=str(e),
                error=str(e),
                done=True,
            )
        except Exception as e:
            logger.exception("Unexpected error in onboarding for %s", request.source)
            yield OnboardingStatus(
                step="error",
                detail=f"Unexpected error: {e}",
                error=str(e),
                done=True,
            )

    def _dispatch(self, request: ScanRequest):
        """Route to the correct entry point handler."""
        if request.entry_point == EntryPoint.REPO_URL:
            yield from self._handle_repo_url(request)
        elif request.entry_point == EntryPoint.SBOM_UPLOAD:
            yield from self._handle_sbom_upload(request)
        elif request.entry_point == EntryPoint.AWS_S3:
            yield from self._handle_aws_s3(request)
        else:
            raise SBOMBridgeError(f"Unknown entry point: {request.entry_point}")

    # ── Entry Point 1: Repo URL ────────────────────────────────────────────

    def _handle_repo_url(self, request: ScanRequest):
        """
        Entry Point 1: GitHub repo URL.

        Step sequence (matches CLAUDE.md Level 3 detect→reuse→generate):
          1. Check GitHub Dependency Graph API
          2. If 404 → "Checking for existing SBOM in repo..."
          3. If none found → "Generating SBOM via syft (this may take ~30s)..."
          4. Parse → return result
        """
        bridge = SBOMBridge(
            github_token=request.github_token or os.environ.get("GITHUB_TOKEN"),
            cache_dir=self.cache_dir,
        )

        repo_slug = bridge._extract_github_slug(request.source)
        if not repo_slug:
            raise SBOMBridgeError(
                f"Not a GitHub URL: {request.source!r}. "
                "Use format: https://github.com/owner/repo"
            )

        yield OnboardingStatus(
            step="checking_github",
            detail=f"Checking GitHub Dependency Graph for {repo_slug}...",
        )

        # Try GitHub Dependency Graph first
        github_result = bridge._fetch_github_sbom(repo_slug)
        if github_result and github_result.package_count > 0:
            yield OnboardingStatus(
                step="sbom_found",
                detail=(
                    f"Found existing SBOM via GitHub Dependency Graph — "
                    f"{github_result.package_count} packages"
                ),
            )
            yield OnboardingStatus(
                step="done",
                detail=f"Ready to enrich {github_result.package_count} packages",
                done=True,
                result=github_result,
            )
            return

        # GitHub Dependency Graph not available — check local (for CLI use)
        yield OnboardingStatus(
            step="checking_local",
            detail="GitHub Dependency Graph not enabled — checking for existing SBOM files...",
        )

        local_dir = Path(".")
        local_result = bridge._discover_local_sbom(local_dir)
        if local_result and local_result.package_count > 0:
            yield OnboardingStatus(
                step="sbom_found",
                detail=(
                    f"Found existing SBOM: {local_result.source_path} — "
                    f"{local_result.package_count} packages"
                ),
            )
            yield OnboardingStatus(
                step="done",
                detail=f"Ready to enrich {local_result.package_count} packages",
                done=True,
                result=local_result,
            )
            return

        # Fallback: generate via syft
        yield OnboardingStatus(
            step="generating_sbom",
            detail=(
                f"No existing SBOM found — generating via syft "
                f"(format: {request.format_preference.value}, ~30s)..."
            ),
        )

        generated = bridge._generate_with_syft(
            request.source,
            request.format_preference,
            repo_slug,
            request.git_sha,
        )

        yield OnboardingStatus(
            step="done",
            detail=f"SBOM generated — {generated.package_count} packages ready to enrich",
            done=True,
            result=generated,
        )

    # ── Entry Point 2: SBOM Upload ─────────────────────────────────────────

    def _handle_sbom_upload(self, request: ScanRequest):
        """
        Entry Point 2: User uploads a CycloneDX or SPDX file.

        Format is auto-detected from content — user does not need to specify.
        Supports: CycloneDX 1.4/1.5 JSON, SPDX 2.3 JSON.
        """
        path = Path(request.source)
        if not path.exists():
            raise SBOMBridgeError(f"Uploaded file not found: {path}")

        yield OnboardingStatus(
            step="detecting_format",
            detail=f"Detecting SBOM format for {path.name}...",
        )

        bridge = SBOMBridge(cache_dir=self.cache_dir)
        detected = bridge._detect_format(path)

        yield OnboardingStatus(
            step="parsing",
            detail=f"Parsing {detected.value} SBOM from {path.name}...",
        )

        result = bridge._parse_file(path, SBOMSource.EXPLICIT_FILE)

        if result.package_count == 0:
            yield OnboardingStatus(
                step="error",
                detail=(
                    f"SBOM parsed but contains 0 packages. "
                    f"Ensure the file is a valid CycloneDX or SPDX 2.3 SBOM."
                ),
                error="empty_sbom",
                done=True,
            )
            return

        yield OnboardingStatus(
            step="done",
            detail=(
                f"Parsed {result.package_count} packages from {path.name} "
                f"({detected.value})"
            ),
            done=True,
            result=result,
        )

    # ── Entry Point 3: AWS S3 ──────────────────────────────────────────────

    def _handle_aws_s3(self, request: ScanRequest):
        """
        Entry Point 3: AWS Inspector S3 bucket.

        Reuses sbom-debt S3 storage backend directly — do not reimplement.
        Expected source format: s3://bucket-name/path/prefix/

        sbom-debt S3 backend handles:
          - AWS credential resolution (profile or IAM role)
          - SPDX 2.3 export enumeration
          - Streaming download to temp files
        """
        if not request.source.startswith("s3://"):
            raise SBOMBridgeError(
                f"AWS S3 entry point requires s3:// URI. Got: {request.source!r}"
            )

        yield OnboardingStatus(
            step="connecting_s3",
            detail=f"Connecting to {request.source}...",
        )

        # Attempt to import sbom-debt S3 backend (production-tested at APA)
        try:
            from sbom_debt.storage.s3 import S3Backend
            use_sbom_debt = True
        except ImportError:
            use_sbom_debt = False
            logger.info("sbom-debt S3 backend not available — using boto3 fallback")

        if use_sbom_debt:
            yield from self._handle_s3_via_sbom_debt(request)
        else:
            yield from self._handle_s3_via_boto3(request)

    def _handle_s3_via_sbom_debt(self, request: ScanRequest):
        """Use sbom-debt S3 backend (preferred — production-tested at APA)."""
        from sbom_debt.storage.s3 import S3Backend
        from sbom_debt.parsing.spdx_parser import SPDXParser

        bucket, prefix = _parse_s3_uri(request.source)
        backend = S3Backend(
            bucket=bucket,
            prefix=prefix,
            aws_profile=request.aws_profile,
        )

        yield OnboardingStatus(
            step="listing_sboms",
            detail=f"Listing SBOM exports in s3://{bucket}/{prefix}...",
        )

        sbom_keys = list(backend.list_sbom_keys())
        if not sbom_keys:
            yield OnboardingStatus(
                step="error",
                detail=f"No SBOM exports found at {request.source}",
                error="no_sboms_found",
                done=True,
            )
            return

        yield OnboardingStatus(
            step="downloading",
            detail=f"Found {len(sbom_keys)} SBOM exports — downloading...",
        )

        all_packages = []
        for key in sbom_keys:
            try:
                local_path = backend.download(key, self.cache_dir)
                parser = SPDXParser()
                raw = parser.parse(str(local_path))
                from sbom_ingestion.sbom_bridge import _sbom_debt_pkg_to_model
                all_packages.extend([_sbom_debt_pkg_to_model(p) for p in raw.packages])
            except Exception as e:
                logger.warning("Could not parse S3 SBOM %s: %s", key, e)

        result = SBOMResult(
            packages=all_packages,
            format=SBOMFormat.SPDX_JSON,
            source=SBOMSource.EXPLICIT_FILE,
            source_path=request.source,
            tool_name="sbom-debt/S3Backend",
        )

        yield OnboardingStatus(
            step="done",
            detail=(
                f"Loaded {result.package_count} packages from "
                f"{len(sbom_keys)} SBOM exports in {request.source}"
            ),
            done=True,
            result=result,
        )

    def _handle_s3_via_boto3(self, request: ScanRequest):
        """Minimal boto3 fallback when sbom-debt is not installed."""
        try:
            import boto3
        except ImportError:
            raise SBOMBridgeError(
                "Neither sbom-debt nor boto3 is installed. "
                "Install sbom-debt (preferred) or boto3 to use the AWS S3 entry point."
            )

        bucket, prefix = _parse_s3_uri(request.source)
        session = (
            boto3.Session(profile_name=request.aws_profile)
            if request.aws_profile
            else boto3.Session()
        )
        s3 = session.client("s3")

        yield OnboardingStatus(
            step="listing_sboms",
            detail=f"Listing SBOM exports in s3://{bucket}/{prefix}...",
        )

        paginator = s3.get_paginator("list_objects_v2")
        keys = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".json") or key.endswith(".spdx"):
                    keys.append(key)

        if not keys:
            yield OnboardingStatus(
                step="error",
                detail=f"No SBOM exports found at {request.source}",
                error="no_sboms_found",
                done=True,
            )
            return

        yield OnboardingStatus(
            step="downloading",
            detail=f"Found {len(keys)} SBOM files — downloading...",
        )

        bridge = SBOMBridge(cache_dir=self.cache_dir)
        all_packages = []
        for key in keys:
            try:
                local_path = self.cache_dir / Path(key).name
                s3.download_file(bucket, key, str(local_path))
                parsed = bridge._parse_file(local_path, SBOMSource.EXPLICIT_FILE)
                all_packages.extend(parsed.packages)
            except Exception as e:
                logger.warning("Could not process S3 object %s: %s", key, e)

        result = SBOMResult(
            packages=all_packages,
            format=SBOMFormat.SPDX_JSON,
            source=SBOMSource.EXPLICIT_FILE,
            source_path=request.source,
            tool_name="boto3/fallback",
        )

        yield OnboardingStatus(
            step="done",
            detail=f"Loaded {result.package_count} packages from {len(keys)} S3 objects",
            done=True,
            result=result,
        )


# ── Factory function (convenience) ────────────────────────────────────────

def create_scan_request(
    source: str,
    github_token: Optional[str] = None,
    aws_profile: Optional[str] = None,
    git_sha: Optional[str] = None,
    format_preference: str = "spdx-json",
) -> ScanRequest:
    """
    Infer entry point from source string and return a ScanRequest.

    Handles the three formats:
      - https://github.com/owner/repo  → REPO_URL
      - s3://bucket/prefix/            → AWS_S3
      - /path/to/sbom.json             → SBOM_UPLOAD
    """
    source = source.strip()
    fmt = SBOMFormat(format_preference) if format_preference in [f.value for f in SBOMFormat] \
        else SBOMFormat.SPDX_JSON

    if source.startswith("s3://"):
        entry_point = EntryPoint.AWS_S3
    elif "github.com/" in source:
        entry_point = EntryPoint.REPO_URL
    elif Path(source).suffix in (".json", ".spdx"):
        entry_point = EntryPoint.SBOM_UPLOAD
    else:
        # Default: treat as repo URL if it looks like owner/repo
        if "/" in source and not source.startswith("/"):
            entry_point = EntryPoint.REPO_URL
            source = f"https://github.com/{source}"
        else:
            entry_point = EntryPoint.SBOM_UPLOAD

    return ScanRequest(
        entry_point=entry_point,
        source=source,
        format_preference=fmt,
        git_sha=git_sha,
        aws_profile=aws_profile,
        github_token=github_token,
    )


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    """Parse s3://bucket/prefix → (bucket, prefix)."""
    without_scheme = uri[len("s3://"):]
    parts = without_scheme.split("/", 1)
    bucket = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""
    return bucket, prefix
