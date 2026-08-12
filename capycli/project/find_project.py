# -------------------------------------------------------------------------------
# Copyright (c) 2019-23 Siemens
# All Rights Reserved.
# Author: thomas.graf@siemens.com
#
# SPDX-License-Identifier: MIT
# -------------------------------------------------------------------------------

import logging
import sys
import traceback
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests
import sw360

import capycli.common.script_base
from capycli.common.print import print_red, print_text, print_yellow
from capycli.main.result_codes import ResultCode

LOG = capycli.get_logger(__name__)


class FindProject(capycli.common.script_base.ScriptBase):
    """Find projects by name on SW360"""

    def list_projects(self, name: str, version: str) -> Any:
        if not self.client:
            print_red("  No client!")
            sys.exit(ResultCode.RESULT_ERROR_ACCESSING_SW360)

        try:
            print_text("  Searching for projects by name")
            projects = self.client.get_projects_by_name(name)

            if not projects:
                print_yellow("  No matching project found!")
                sys.exit(ResultCode.RESULT_PROJECT_NOT_FOUND)

            for project in projects:
                self.display_project(project)

        except Exception as ex:
            print_red(
                "Error searching for project: \n" +
                repr(ex) + "\n" +
                str(traceback.format_exc()))

    def display_project(self, project: Optional[Dict[str, Any]], pid: str = "") -> None:
        if not self.client:
            print_red("  No client!")
            sys.exit(ResultCode.RESULT_ERROR_ACCESSING_SW360)

        if not project:
            project = self.client.get_project(pid)

        if not project:
            print_red("Cannot read project!")
            return

        href = project["_links"]["self"]["href"]
        if "version" not in project:
            print_text(
                "    " + project["name"] + " => ID = " +
                self.client.get_id_from_href(href))
        else:
            print_text(
                "    " + project["name"] + ", " + project["version"] +
                " => ID = " + self.client.get_id_from_href(href))

    def check_project_id(self, project_id: str) -> None:
        if not self.client:
            print_red("  No client!")
            sys.exit(ResultCode.RESULT_ERROR_ACCESSING_SW360)

        try:
            project = self.client.get_project(project_id)
            if not project:
                print_yellow("No project with given id found!")
                return

            print_text(
                "Project found, name = " + project["name"] +
                ", version = " + project["version"])
        except sw360.SW360Error as swex:
            if swex.response is None:
                print_red("Unknown error: " + swex.message)
            elif swex.response.status_code == requests.codes['not_found']:
                print_yellow(f"Project with id {project_id} not found!")
            else:
                print_red("Error retrieving project data.")
                print_red("  Status Code: " + str(swex.response.status_code))
                if swex.message:
                    print_red("    Message: " + swex.message)
        except Exception as ex:
            print_yellow("Error searching for project: " + repr(ex))

    def find_project_with_fallback(self, name: str, version: str, quiet: bool = False) -> str:
        """Find a project ID using multiple fallback methods.

        Method 1: Search by name via capycli (get_projects_by_name)
        Method 2: Query SW360 search API directly
        Method 3: List all projects and filter by name+version

        :param quiet: when True, suppress all status output (only the ID is meaningful)
        """
        if not self.client:
            print_red("  No client!")
            sys.exit(ResultCode.RESULT_ERROR_ACCESSING_SW360)

        project_id = ""

        # Method 1: Search by name via SW360 API
        if not quiet:
            print_text("  Method 1: Searching via get_projects_by_name...")
        try:
            projects = self.client.get_projects_by_name(name)
            if projects:
                for project in projects:
                    if "version" in project and project["version"].lower() == version.lower():
                        href = project["_links"]["self"]["href"]
                        project_id = self.client.get_id_from_href(href)
                        if not quiet:
                            print_text("  Found project ID via search: " + project_id)
                        return project_id
        except Exception:
            pass

        # Method 2: Query SW360 search API directly
        if not quiet:
            print_text("  Method 2: Querying SW360 search API directly...")
        try:
            search_url = (
                self.sw360_url + "resource/api/search?type=project&searchText="
                + quote(name) + "&page=0&page_entries=10")
            data = self.client.api_get(search_url)
            if data and "_embedded" in data and "sw360:projects" in data["_embedded"]:
                for proj in data["_embedded"]["sw360:projects"]:
                    proj_name = proj.get("name", "")
                    proj_ver = proj.get("version", "")
                    if proj_name.lower() == name.lower() and proj_ver.lower() == version.lower():
                        href = proj["_links"]["self"]["href"]
                        project_id = self.client.get_id_from_href(href)
                        if not quiet:
                            print_text("  Found project ID via API search: " + project_id)
                        return project_id
        except Exception as ex:
            if not quiet:
                print_yellow("  API search failed: " + repr(ex))

        # Method 3: List all projects
        if not quiet:
            print_text("  Method 3: Listing all projects...")
        try:
            data = self.client.get_projects()
            if data and "_embedded" in data and "sw360:projects" in data["_embedded"]:
                for proj in data["_embedded"]["sw360:projects"]:
                    proj_name = proj.get("name", "")
                    proj_ver = proj.get("version", "")
                    if proj_name.lower() == name.lower() and proj_ver.lower() == version.lower():
                        href = proj["_links"]["self"]["href"]
                        project_id = self.client.get_id_from_href(href)
                        if not quiet:
                            print_text("  Found project ID via listing: " + project_id)
                        return project_id
        except Exception as ex:
            if not quiet:
                print_yellow("  Project listing failed: " + repr(ex))

        return ""

    def run(self, args: Any) -> None:
        """Main method()"""
        if args.debug:
            global LOG
            LOG = capycli.get_logger(__name__)
        else:
            # suppress (debug) log output from requests and urllib
            logging.getLogger("requests").setLevel(logging.WARNING)
            logging.getLogger("urllib3").setLevel(logging.WARNING)
            logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)

        if args.help:
            print("usage: CaPyCli project find [-h] -t TOKEN -name NAME -version VERSION [-id PROJECT_ID] [--id-only]")
            print("")
            print("optional arguments:")
            print("    -h, --help            show this help message and exit")
            print("    -name NAME            name of the project")
            print("    -version VERSION      version of the project")
            print("    -id PROJECT_ID        SW360 id of the project, supersedes name and version parameters")
            print("    --id-only             only output the project ID (for scripting)")
            return

        if not args.id_only:
            print_text(
                "\n" + capycli.get_app_signature() +
                " - Find a project by name\n")

        if not self.login(token=args.sw360_token, url=args.sw360_url, oauth2=args.oauth2):
            print_red("ERROR: login failed!")
            sys.exit(ResultCode.RESULT_AUTH_ERROR)

        name: str = args.name
        version: str = ""
        if args.version:
            version = args.version

        if args.id:
            if args.id_only:
                print(args.id)
            else:
                self.check_project_id(args.id)
        elif args.id_only:
            # Use the full fallback chain when --id-only is specified
            if not name or not version:
                print_red("--id-only requires -name and -version!")
                sys.exit(ResultCode.RESULT_COMMAND_ERROR)
            pid = self.find_project_with_fallback(name, version, quiet=True)
            if pid:
                print(pid)
            else:
                sys.exit(ResultCode.RESULT_PROJECT_NOT_FOUND)
        else:
            if name:
                if version:
                    # find_project() is part of script_base.py
                    pid = self.find_project(name, version)
                    if pid:
                        self.display_project(None, pid)
                    else:
                        print_yellow("\nNo matching project found!")
                else:
                    self.list_projects(name, version)
            else:
                print_red("Neither name nor external id specified!")
                sys.exit(ResultCode.RESULT_COMMAND_ERROR)
