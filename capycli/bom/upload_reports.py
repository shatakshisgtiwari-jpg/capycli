# -------------------------------------------------------------------------------
# Copyright (c) 2024-2026 Siemens
# All Rights Reserved.
#
# SPDX-License-Identifier: MIT
# -------------------------------------------------------------------------------

"""
Upload scan reports (FOSSology, SPDX, etc.) to existing SW360 releases.

This command reads an SBOM that has already been mapped to SW360 (via
`capycli bom map` or `capycli bom createcomponents`) and uploads per-dependency
scan report files as attachments to each release that has a sw360Id.

Report files must be named: {component_name}@{component_version}.spdx.json

Usage:
    capycli bom uploadreports -i mapped_bom.cdx.json --report-dir ./scan-reports/
    capycli bom uploadreports -i mapped_bom.cdx.json --report-dir ./scan-reports/ --filetype CLEARING_REPORT

Report file naming:
    Files in the report directory should be named:
    {component_name}@{component_version}.spdx.json
    Example: lodash@4.17.21.spdx.json

    Matching priority:
    1. Exact match: {name}@{version}.spdx.json
    2. Name-only match: {name}@{any_version}.*

Attachment types supported by SW360:
    COMPONENT_LICENSE_INFO_XML  — FOSSology/SPDX scan results (default)
    CLEARING_REPORT             — Legal clearing report
    SOURCE                      — Source code archive
    BINARY                      — Binary archive
    DOCUMENT                    — General document
    README_OSS                  — OSS readme file
"""

import hashlib
import os
import re
import sys
from typing import Any, Dict, Optional

from cyclonedx.model.bom import Bom
from sw360 import SW360Error

import capycli
import capycli.common.script_base
from capycli.common.capycli_bom_support import CaPyCliBom, CycloneDxSupport, SbomWriter
from capycli.common.print import print_green, print_red, print_text, print_yellow
from capycli.main.result_codes import ResultCode


class BomUploadReports(capycli.common.script_base.ScriptBase):
    """
    Upload scan reports to existing SW360 releases.

    Reuses:
      - ScriptBase.login()  → same auth as all CaPyCLI commands
      - self.client.get_release()
      - self.client.get_attachment_infos_for_release()
      - self.client.upload_release_attachment()
    """

    def _has_conflicting_attachment(
            self, release_id: str, filename: str, upload_type: str) -> bool:
        """Check whether an attachment with the same filename already exists on the release.

        SW360 does not allow two attachments with the same filename on one release.
        We never delete existing attachments — if a conflict is found, the caller
        should report an error and skip the upload instead.

        @params:
            release_id - SW360 release ID
            filename   - the basename of the report file to check for
            upload_type - SW360 attachment type to match
        """
        if not self.client:
            return False
        try:
            self.debug_sw360_request(
                "GET",
                self.sw360_api_url(f"resource/api/releases/{release_id}/attachments"),
                release_id=release_id,
                purpose="check existing attachments")
            attachments = self.client.get_attachment_infos_for_release(release_id)
            for att in attachments:
                if att.get("filename", "") == filename and att.get("attachmentType", "") == upload_type:
                    return True
        except SW360Error as swex:
            self.debug_sw360_error(swex)
            print_yellow(f"    Cannot check existing attachments: {self.get_error_message(swex)}")
        return False

    def find_report_file(self, component_name: str, component_version: str,
                         report_dir: str) -> Optional[str]:
        """Find a report file for a specific component in the report directory.

        Searches for report files using the following priority order:
        1. Exact match: {name}@{version}.spdx.json
        2. Name-only match: {name}@*.* (any version)
        3. Sanitized name match: special chars replaced with underscores

        @params:
            component_name   - Required : component name from SBOM
            component_version - Required : component version from SBOM
            report_dir       - Required : directory containing report files

        @returns:
            Full path to the report file, or None if not found
        """
        if not os.path.isdir(report_dir):
            return None

        # Get all files in directory once
        all_files = [
            f for f in os.listdir(report_dir)
            if os.path.isfile(os.path.join(report_dir, f))
        ]

        # Try exact match: {name}@{version}.*
        exact_pattern = f"{component_name}@{component_version}"
        for filename in all_files:
            if filename.startswith(exact_pattern):
                return os.path.join(report_dir, filename)

        # Try name-only match: {name}@*.*
        for filename in all_files:
            if filename.startswith(component_name + "@"):
                return os.path.join(report_dir, filename)

        # Try sanitized name match (special chars replaced with underscores)
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', component_name)
        safe_version = re.sub(r'[^a-zA-Z0-9._-]', '_', component_version or "")

        # Sanitized exact match: {safe_name}@{safe_version}.*
        safe_exact = f"{safe_name}@{safe_version}"
        for filename in all_files:
            if filename.startswith(safe_exact):
                return os.path.join(report_dir, filename)

        # Sanitized name-only match: {safe_name}@*.*
        for filename in all_files:
            if filename.startswith(safe_name + "@"):
                return os.path.join(report_dir, filename)

        return None

    def upload_reports_per_dependency(self, sbom: Bom, report_dir: str,
                                      upload_type: str, upload_comment: str,
                                      skip_existing: bool = True) -> Dict[str, int]:
        """Upload per-dependency scan reports to SW360 releases.

        Each component in the SBOM is matched with a corresponding report file
        in the report directory. Report files should be named:
        {component_name}@{component_version}.spdx.json

        @params:
            sbom           - Required : the bill of materials (BOM)
            report_dir     - Required : directory containing per-dependency report files
            upload_type    - Required : SW360 attachment type
            upload_comment - Required : comment for the attachment
            skip_existing  - Optional : skip if same SHA-1 already attached (default: True)

        @returns:
            Dictionary with counts: uploaded, skipped, failed, no_id, no_report
        """
        report = {"uploaded": 0, "skipped": 0, "failed": 0, "no_id": 0, "no_report": 0}

        print_text(f"  Report directory: {report_dir}")
        print_text(f"  Upload type:      {upload_type}")
        print_text(f"  Comment:          {upload_comment}")
        print_text("")

        for component in sbom.components:
            item_name = f"{component.name}@{component.version}" if component.version else component.name

            # Get SW360 release ID from SBOM (set by 'bom map' or 'bom createcomponents')
            release_id = CycloneDxSupport.get_property_value(
                component, CycloneDxSupport.CDX_PROP_SW360ID)

            if not release_id:
                report["no_id"] += 1
                print_yellow(f"  {item_name}: No sw360Id — skipping (run 'bom map' first)")
                continue

            print_text(f"  {item_name} (release: {release_id[:8]}...)")

            # Find the report file for this component
            report_file = self.find_report_file(
                component.name,
                component.version or "",
                report_dir)

            if not report_file:
                report["no_report"] += 1
                print_yellow(f"    No report file found in {report_dir}")
                continue

            # Compute SHA-1 of report file
            with open(report_file, "rb") as f:
                file_content = f.read()
            local_hash = hashlib.sha1(file_content).hexdigest()
            print_text(f"    Report SHA-1: {local_hash}")
            print_text(f"    Report size:  {len(file_content):,} bytes")

            # Check existing attachments for dedup
            should_upload = True
            if skip_existing and self.client:
                try:
                    self.debug_sw360_request(
                        "GET",
                        self.sw360_api_url(f"resource/api/releases/{release_id}/attachments"),
                        release_id=release_id,
                        purpose="check duplicate report hash")
                    attachments = self.client.get_attachment_infos_for_release(release_id)
                    for att in attachments:
                        if (att.get("attachmentType") == upload_type and
                                att.get("sha1") == local_hash):
                            report["skipped"] += 1
                            print_green(f"    Skipped — same {upload_type} already attached (SHA-1 match)")
                            should_upload = False
                            break
                except SW360Error as swex:
                    self.debug_sw360_error(swex)
                    print_yellow(f"    Cannot check existing attachments: {self.get_error_message(swex)}")
                    # Proceed to upload anyway

            # Upload the report only if not skipped
            if should_upload:
                if self.client:
                    # SW360 rejects duplicate filenames on a release — never delete
                    # existing data, just report the conflict and skip this upload
                    if self._has_conflicting_attachment(
                            release_id, os.path.basename(report_file), upload_type):
                        report["failed"] += 1
                        print_red(
                            f"    An attachment named {os.path.basename(report_file)} "
                            "already exists on this release — skipping upload")
                        continue
                    try:
                        self.debug_sw360_request(
                            "POST",
                            self.sw360_api_url(f"resource/api/releases/{release_id}/attachments"),
                            release_id=release_id,
                            upload_file=report_file,
                            attachment_type=upload_type,
                            attachment_comment=upload_comment,
                            filename=os.path.basename(report_file))
                        self.client.upload_release_attachment(
                            release_id,
                            report_file,
                            upload_type=upload_type,
                            upload_comment=upload_comment)
                        report["uploaded"] += 1
                        print_green(f"    Uploaded {os.path.basename(report_file)} as {upload_type}")
                    except SW360Error as swex:
                        self.debug_sw360_error(swex)
                        report["failed"] += 1
                        print_red(f"    Upload failed: {self.get_error_message(swex)}")
                else:
                    report["failed"] += 1
                    print_red("    No SW360 client!")

        return report

    def run(self, args: Any) -> None:
        """Main method

        @params:
            args - command line arguments
        """
        print_text(
            "\n" + capycli.get_app_signature() +
            " - Upload scan reports to existing SW360 releases\n")

        if args.help:
            print("usage: capycli bom uploadreports -i bom.json --report-dir ./reports/ [options]")
            print("")
            print("Upload per-dependency scan reports (FOSSology, SPDX, etc.) to existing SW360 releases.")
            print("")
            print("Report file naming:")
            print("  Files should be named: {component_name}@{component_version}.spdx.json")
            print("  Example: lodash@4.17.21.spdx.json")
            print("")
            print("optional arguments:")
            print("    -h, --help            show this help message and exit")
            print("    -i INPUTFILE          input SBOM file to read from (JSON)")
            print("    --report-dir DIR      directory with per-dependency reports")
            print("    --filetype TYPE       SW360 attachment type")
            print("                          (default: COMPONENT_LICENSE_INFO_XML)")
            print("    --comment COMMENT     attachment comment")
            print("                          (default: 'Scan report uploaded by CaPyCLI')")
            print("    --force               upload even if same SHA-1 already exists")
            print("    -url SW360_URL        use this URL for access to SW360")
            print("    -t SW360_TOKEN        use this token for access to SW360")
            print("    -oa, --oauth2         this is an oauth2 token")
            print("    -o OUTPUTFILE         output SBOM file to write to")
            print("    -v                    be verbose")
            return

        # Validate inputs
        if not args.inputfile:
            print_red("No input file specified!")
            sys.exit(ResultCode.RESULT_COMMAND_ERROR)

        if not os.path.isfile(args.inputfile):
            print_red("Input file not found: " + args.inputfile)
            sys.exit(ResultCode.RESULT_FILE_NOT_FOUND)

        report_dir = getattr(args, "report_dir", "") or ""

        if not report_dir:
            print_red("No report source specified! Use --report-dir <dir>")
            sys.exit(ResultCode.RESULT_COMMAND_ERROR)

        if not os.path.isdir(report_dir):
            print_red("Report directory not found: " + report_dir)
            sys.exit(ResultCode.RESULT_FILE_NOT_FOUND)

        upload_type = getattr(args, "filetype", None) or "COMPONENT_LICENSE_INFO_XML"
        upload_comment = getattr(args, "comment", None) or "Scan report uploaded by CaPyCLI"
        skip_existing = not getattr(args, "force", False)

        # Load SBOM
        print_text("Loading SBOM file " + args.inputfile)
        try:
            bom = CaPyCliBom.read_sbom(args.inputfile)
        except Exception as ex:
            print_red("Error reading input SBOM file: " + repr(ex))
            sys.exit(ResultCode.RESULT_ERROR_READING_BOM)

        if args.verbose:
            print_text(f"  {len(bom.components)} components read from SBOM file")

        # Authenticate to SW360
        if not self.login(token=args.sw360_token, url=args.sw360_url, oauth2=args.oauth2):
            print_red("Login failed!")
            sys.exit(ResultCode.RESULT_AUTH_ERROR)

        print_text(f"\nUploading per-dependency reports from {report_dir} to SW360 releases ...")
        print_text("")

        result = self.upload_reports_per_dependency(
            bom, report_dir, upload_type, upload_comment, skip_existing)

        # Print summary
        print_text("")
        print_text("=" * 60)
        print_text("Upload Summary:")
        print_green(f"  Uploaded:  {result['uploaded']}")
        print_text(f"  Skipped:   {result['skipped']}")
        print_red(f"  Failed:    {result['failed']}")
        print_yellow(f"  No ID:     {result['no_id']}")
        print_yellow(f"  No Report: {result['no_report']}")
        print_text("=" * 60)

        # Write updated SBOM if output specified
        if args.outputfile:
            print_text(f"\nWriting SBOM to {args.outputfile}")
            try:
                SbomWriter.write_to_json(bom, args.outputfile, True)
            except Exception as ex:
                print_red("Error writing SBOM file: " + repr(ex))
                sys.exit(ResultCode.RESULT_ERROR_WRITING_BOM)

        # Exit with error if any failures
        if result["failed"] > 0:
            sys.exit(ResultCode.RESULT_ERROR_ACCESSING_SW360)
