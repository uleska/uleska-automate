#!/usr/bin/env python3

import requests
import json
import argparse
import time
import sys

from api.scan_api import scan_with_toolkit
from model.failure_thresholds import FailureThresholds
from service.report import print_output_and_check_thresholds
from service.scan import wait_for_scan_to_finish
from service.toolkit import get_toolkit_id_from_name


class issue_info:
    title = ""
    tool = ""
    total_cost = 0
    CVSS = ""
    CVSS_value = 0.0
    affectedURL = ""
    summary = ""
    severity = ""
    explanation = ""
    recommendation = ""


class ids:
    application_id = ""
    version_id = ""





class version_info:
    name = ""
    id = ""


def _main():
    # Capture command line arguments
    arguments = sys.argv

    # Capture command line arguments
    arg_options = argparse.ArgumentParser(
        fromfile_prefix_chars='@', description="Uleska command line interface. To identify the project/pipeline to test you can specify either --application_name and --version_name, or --application and --version (passing GUIDs). Arguments can also be stored in an argparse configuration file specified with 'uleska-automate @args.txt'. (Version 0.10)", )
    arg_options.add_argument('--uleska_host',
                             help="URL to the Uleska host (e.g. https://s1.uleska.com/) (note final / is required)",
                             required=True, type=str)
    arg_options.add_argument('--token', help="String for the authentication token", required=True, type=str)

    arg_options.add_argument('--application_id', help="GUID for the application to reference", type=str)
    arg_options.add_argument('--version_id', help="GUID for the application version/pipeline to reference", type=str)
    arg_options.add_argument('--application_name', help="Name for the application to reference", type=str)
    arg_options.add_argument('--version_name', help="Name for the version/pipeline to reference", type=str)
    arg_options.add_argument('--toolkit_name', help="The name of the toolkit you would like to use to scan.  Note: for backwards compatibility you can call the CLI without this argument, but this will be depreciated in the future.", type=str, default="")

    arg_options.add_argument('--update_sast',
                             help="Add or update a SAST pipeline.  Requires an pre-existing application. See documentation for other settings",
                             action="store_true")
    arg_options.add_argument('--sast_git', help="Git URL for SAST repo.  Required with --update_sast.", type=str)
    arg_options.add_argument('--sast_username',
                             help="If repo requires authentication, this is the username to use.  Optional with --update_sast.",
                             type=str)
    arg_options.add_argument('--sast_token',
                             help="If repo requires authentication, this is the token value to use.  Optional with --update_sast.",
                             type=str)

    arg_options.add_argument('--tools',
                             help="List of tool names to use for this version.  Optional with --update_sast.  Comma separated.  Note this option is now depreciated.",
                             type=str)

    arg_options.add_argument('--update_container',
                             help="Update a container pipeline.  Requires an pre-existing application/config. See documentation for other settings",
                             action="store_true")
    arg_options.add_argument('--container_image', help="Name of image to use. Required with --update_container.",
                             type=str)
    arg_options.add_argument('--container_tag', help="Tag to use. Required with --update_container.", type=str)
    arg_options.add_argument('--container_connection',
                             help="Connection name to use for container access. Optional with --update_container.  If not included Docker Hub is assumed.",
                             type=str)

    arg_options.add_argument('--test',
                             help="Run tests only for the application and version referenced, do not wait for the results",
                             action="store_true")
    arg_options.add_argument('--test_and_results',
                             help="Run tests for the application and version referenced, and return the results from the last as JSON",
                             action="store_true")
    arg_options.add_argument('--test_and_compare',
                             help="Run tests for the application and version referenced, and return any differences in the results from the last test",
                             action="store_true")

    arg_options.add_argument('--latest_results',
                             help="Retrieve the latest test results for application and version referenced",
                             action="store_true")
    arg_options.add_argument('--compare_latest_results',
                             help="Retrieve the latest test results for version and compare", action="store_true")
    arg_options.add_argument('--print_json', help="Print the relevant output as JSON to stdout", action="store_true")
    arg_options.add_argument('--get_ids', help="Retrieve GUID for the application_name and version_name supplied",
                             action="store_true")
    arg_options.add_argument('--app_stats', help="Retrieve the latest risk and vulnerabiltiy for the whole application",
                             action="store_true")

    arg_options.add_argument('--fail_if_issue_risk_over',
                             help="Causes the CLI to return a failure if any new issue risk is over the integer specified",
                             type=str)
    arg_options.add_argument('--fail_if_risk_over',
                             help="Causes the CLI to return a failure if the risk is over the integer specified",
                             type=str)
    arg_options.add_argument('--fail_if_risk_change_over',
                             help="Causes the CLI to return a failure if the percentage change of increased risk is over the integer specified. Requires 'test_and_compare' or 'compare_latest_results' functions",
                             type=str)
    arg_options.add_argument('--fail_if_issues_over',
                             help="Causes the CLI to return a failure if the number of issues is over the integer specified",
                             type=str)
    arg_options.add_argument('--fail_if_issues_change_over',
                             help="Causes the CLI to return a failure if the percentage change in new issues is over the integer specified.  Requires 'test_and_compare' or 'compare_latest_results' function",
                             type=str)
    arg_options.add_argument('--fail_if_CVSS_over',
                             help="Causes the CLI to return a failure if the any new issue has a CVSS over the integer specified.  Requires 'test_and_compare' or 'compare_latest_results' function",
                             type=str)

    arg_options.add_argument('--debug', help="Prints debug messages", action="store_true")

    args = arg_options.parse_args()

    host = ""
    application = ""  # id
    version = ""  # id
    token = ""

    test_and_compare = False
    test_and_results = False
    test = False
    latest_results = False
    compare_latest_results = False
    add_version = False
    get_ids = False
    app_stats = False
    print_json = False
    update_sast = False
    update_container = False

    sast_git = ""
    sast_username = ""
    sast_token = ""

    tools = ""

    container_image = ""
    container_tag = ""
    container_connection = ""

    thresholds: FailureThresholds = FailureThresholds()

    application_name = ""
    version_name = ""

    debug = False

    # Set debug
    if args.debug:
        debug = True
        print("Debug enabled")

    # Grab the host from the command line arguments
    if args.uleska_host is not None:
        host_tmp = args.uleska_host
        
        # Make sure last character of host is "/"
        host_striped = host_tmp.strip()
        
        if host_striped[-1] != '/':
            host = host_striped + '/'
        else:
            host = host_striped

        if debug:
            print("Host: " + host)

    # Grab the application id from the command line arguments
    if args.application_id is not None:
        application = args.application_id

        if debug:
            print("Application id: " + application)

    # Grab the version from the command line arguments
    if args.version_id is not None:
        version = args.version_id

        if debug:
            print("Version id: " + version)

    # Grab the token from the command line arguments
    if args.token is not None:
        token = args.token

        if debug:
            print("Token: " + token)

    # Set test_and_compare
    if args.test_and_compare:
        test_and_compare = True

        if debug:
            print("test_and_compare enabled")

    # Set test_and_results
    if args.test_and_results:
        test_and_results = True

        if debug:
            print("test_and_results enabled")

    # Set test
    if args.test:
        test = True

        if debug:
            print("test enabled")

    # Set latest_results
    if args.latest_results:
        latest_results = True

        if debug:
            print("latest_results enabled")

    # Set compare_latest_results
    if args.compare_latest_results:
        compare_latest_results = True

        if debug:
            print("compare_latest_results enabled")

    # Set print_json flag
    if args.print_json:
        print_json = True

    # Set get_ids
    if args.get_ids:
        get_ids = True

        if debug:
            print("get_ids enabled")

    # Set compare_app_results
    if args.app_stats:
        app_stats = True

        if debug:
            print("app_stats enabled")

    # Grab the application_name from the command line arguments
    if args.application_name is not None:
        application_name = args.application_name

        if debug:
            print("Application name: " + application_name)

    # Grab the version_name from the command line arguments
    if args.version_name is not None:
        version_name = args.version_name

        if debug:
            print("Version name: " + version_name)

    # Grab SAST Pipeline from the command line arguments
    if args.update_sast:
        update_sast = True

        if debug:
            print("update_sast is set")

    # Grab the SAST Git from the command line arguments
    if args.sast_git is not None:
        sast_git = args.sast_git

        if debug:
            print("sast_git: " + sast_git)

    # Grab the SAST username from the command line arguments
    if args.sast_username is not None:
        sast_username = args.sast_username

        if debug:
            print("sast_username: " + sast_username)

    # Grab the SAST token from the command line arguments
    if args.sast_token is not None:
        sast_token = args.sast_token

        if debug:
            print("sast_token: " + sast_token)

    # Grab the tools string from the command line arguments (comma separated at this stage)
    if args.tools is not None:
        tools = args.tools

        if debug:
            print("tools: " + tools)

    # Grab container Pipeline from the command line arguments
    if args.update_container:
        update_container = True

        if debug:
            print("update_container is set")

    # Grab the container image from the command line arguments
    if args.container_image is not None:
        container_image = args.container_image

        if debug:
            print("container_image: " + container_image)

    # Grab the container tag from the command line arguments
    if args.container_tag is not None:
        container_tag = args.container_tag

        if debug:
            print("container_tag: " + container_tag)

    # Grab the container connection from the command line arguments
    if args.container_connection is not None:
        container_connection = args.container_connection

        if debug:
            print("container_connection: " + container_connection)

    # Grab the fail_if_issue_risk_over from the command line arguments
    if args.fail_if_issue_risk_over is not None:
        thresholds.fail_if_issue_risk_over = int(args.fail_if_issue_risk_over)

        if debug:
            print("fail_if_issue_risk_over: " + str(thresholds.fail_if_issue_risk_over))

    # Grab the fail_if_risk_over from the command line arguments
    if args.fail_if_risk_over is not None:
        thresholds.fail_if_risk_over = int(args.fail_if_risk_over)

        if debug:
            print("fail_if_risk_over: " + str(thresholds.fail_if_risk_over))

    # Grab the fail_if_risk_change_over from the command line arguments
    if args.fail_if_risk_change_over is not None:
        thresholds.fail_if_risk_change_over = int(args.fail_if_risk_change_over)

        if debug:
            print("fail_if_risk_change_over: " + str(thresholds.fail_if_risk_change_over))

    # Grab the fail_if_issues_over from the command line arguments
    if args.fail_if_issues_over is not None:
        thresholds.fail_if_issues_over = int(args.fail_if_issues_over)

        if debug:
            print("fail_if_issues_over: " + str(thresholds.fail_if_issues_over))

    # Grab the fail_if_issues_change_over from the command line arguments
    if args.fail_if_issues_change_over is not None:
        thresholds.fail_if_issues_change_over = int(args.fail_if_issues_change_over)

        if debug:
            print("fail_if_issues_change_over: " + str(thresholds.fail_if_issues_change_over))

    # Grab the fail_if_CVSS_over from the command line arguments
    if args.fail_if_CVSS_over is not None:
        thresholds.fail_if_CVSS_over = float(args.fail_if_CVSS_over)

        if debug:
            print("fail_if_CVSS_over: " + str(thresholds.fail_if_CVSS_over))

    if app_stats and application_name != "":
        # user is requesting app results (therefore won't pass an individual version)
        pass

    if update_sast:
        # when update_sast is called, the version_name will be checked, updated, or added

        # check we have application_name and version_name (required)
        if application_name == "" or version_name == "":
            print("Error, for --update_sast both --application_name and --version_name are required.")
            sys.exit(2)

        # map application_name to an id
        application = run_map_app_name_to_id(host, application_name, token, print_json)

        # attempt to get the version id for the passed version name. This will return either the ID if it exists, or "" if it doesn't
        version = run_check_for_existing_version(host, application_name, version_name, token, print_json)

        # check the tools to use (these may be being updated)
        tools_list = tools.split(",")

        # get list of tools & details from the system as JSON
        system_tools_list = run_get_tools_details(host, token, print_json)

        # TODO - right now we don't check that
        #  a) if any tool supplied by user in tools_list doesn't match the system tools list
        #  b) we report on that (error to the user) or how to handle it

        # create a store for the tools we're going to add
        tools_to_add = []

        # build the tools body up so we can submit with our version creation/update
        # iterate through the system_tools_list we got and extract matching info
        for tool in system_tools_list:

            if tool['title'] in tools_list:
                # tool.remove('icon') # we don't use this

                this_tool = {}
                this_tool['toolName'] = tool['name']

                orig_string = json.dumps(tool)

                this_tool['toolJson'] = orig_string

                tools_to_add.append(this_tool)

            # What to do if a tool is supplied that is not in the list? TODO

        # check if version_name exists for the app
        if version == "":

            # this version_name doesn't exist, create it depending on authentication needed
            if sast_git == "":
                # if creating a new version, we need the git URL, return an error
                print("Error, when passing --update_sast for a new version, --sast_git URL is required")
                sys.exit(2)

            if sast_username != "":
                # user has passed sast_username, which means they'll need to pass the token

                if sast_token == "":
                    print("Error, when passing --sast_username to setup authentication, --sast_token is required")
                    sys.exit(2)

                # "user has passed both sast_username and sast_token
                version = run_create_version_with_credentials(host, application, version_name, token, print_json,
                                                              sast_git, sast_username, sast_token, tools_to_add)

            else:
                # user has not passed sast_username, so assume no credentials needed for this repo
                version = run_create_version(host, application, version_name, token, print_json, sast_git, tools_to_add)

        else:

            version_data = {}
            # version does exist, so get the current info (as JSON), and update it
            version_data = run_get_verison_info(host, application, version, token, print_json)

            # if sast_git was supplied, update this
            if sast_git != "":
                # "updating sast_git

                version_data['scmConfiguration']['address'] = sast_git

            # if username was passed, update it
            if sast_username != "":
                # updating username
                version_data['scmConfiguration']['identity'] = sast_username
                version_data['scmConfiguration']['authenticationType'] = "USER_PASS"

            # if sast_token was passed, update it
            # TODO - we don't check if this is passed with sast_username - should we require this?  Should someone update username but not token?
            if sast_token != "":
                # updating sast_token
                version_data['scmConfiguration']['secret'] = sast_token

            # update the version
            run_update_version(host, application, version, token, print_json, version_data, tools_to_add)





    elif update_container:
        # when update_container is called, the container config will be updated

        # check we have application_name and version_name (required)
        if application_name == "" or version_name == "":
            print("Error, for --update_container both --application_name and --version_name are required.")
            sys.exit(2)

        # check we have container_image and container_tag (required)
        if container_image == "" or container_tag == "":
            print("Error, for --update_container both --container_image and --container_tag are required.")
            sys.exit(2)

        # map application_name to an id
        application = run_map_app_name_to_id(host, application_name, token, print_json)

        # attempt to get the version id for the passed version name. This will return either the ID if it exists, or "" if it doesn't
        version = run_check_for_existing_version(host, application_name, version_name, token, print_json)

        connection_id = ""

        # check if a connection was specified, if so, get the corresponding id
        if container_connection != "":
            connection_id = run_map_container_name_to_id(host, container_connection, token, print_json)
        else:
            connection_id = "null"

        # update the container config
        run_update_container_config(host, application, version, container_image, container_tag, connection_id, token,
                                    print_json)



    elif not app_stats and (application_name != "" or version_name != ""):
        if not print_json:
            print("Application or version name passed, looking up ids...")

        results = map_app_name_and_version_to_ids(host, application_name, version_name, token, print_json)

        application = results.application_id
        version = results.version_id

    toolkit_id = None
    if args.toolkit_name != "":
        toolkit_id = get_toolkit_id_from_name(host, token, args.toolkit_name, print_json)

    # Args retrieved, now decide what we're doing
    if get_ids:
        # No action as map_app_name_and_version_to_ids will have already returned the ids
        pass
    elif app_stats:
        run_app_stats(host, application_name, token, print_json, thresholds)
    elif test_and_compare:
        if toolkit_id is not None:
            run_scan_with_toolkits_and_compare(host, application, version, token, toolkit_id, print_json, thresholds)
        else:
            run_test_and_compare(host, application, version, token, print_json, thresholds)
    elif test_and_results:
        if toolkit_id is not None:
            run_scan_with_toolkits_and_results(host, application, version, token, toolkit_id, print_json, thresholds)
        else:
            run_test_and_results(host, application, version, token, print_json, thresholds)
    elif test:
        if toolkit_id is not None:
            scan_with_toolkit(host, token, application, version, toolkit_id)
        else:
            run_scan(host, application, version, token, print_json)
    elif latest_results:
        run_latest_results(host, application, version, token, print_json, thresholds)
    elif compare_latest_results:
        run_compare_latest_results(host, application, version, token, print_json, thresholds)
    else:
        print("No recognised function specified.")
        sys.exit(2)


def run_test_and_results(host, application, version, token, print_json, thresholds):
    # First run a new scan in blocking mode (so we can check the results afterwards
    run_scan_blocking(host, application, version, token, print_json)

    reports = get_reports_list(host, application, version, token, print_json)

    report_info = get_report_info(host, application, version, token, reports, -1, print_json)

    report_issues = build_and_print_report_issues(report_info, "Latest", print_json)

    print_output_and_check_thresholds(report_issues, print_json, thresholds)


def run_latest_results(host, application, version, token, print_json, thresholds):
    reports = get_reports_list(host, application, version, token, print_json)

    report_info = get_report_info(host, application, version, token, reports, -1, print_json)

    results = build_and_print_report_issues(report_info, "Latest", print_json)

    max_cvss_found = 0.0
    max_issue_risk_found = 0

    output = {}
    results_to_print = []
    overall_risk = 0

    for i in results:

        json_issue = {}
        json_issue['title'] = i.title
        json_issue['tool'] = i.tool
        json_issue['risk'] = i.total_cost
        json_issue['cvss'] = i.CVSS
        json_issue['summary'] = i.summary
        json_issue['severity'] = i.severity
        json_issue['explanation'] = i.explanation
        json_issue['recommendation'] = i.recommendation

        if i.CVSS_value > max_cvss_found:
            max_cvss_found = i.CVSS_value

        if i.total_cost > max_issue_risk_found:
            max_issue_risk_found = i.total_cost

        overall_risk += i.total_cost

        results_to_print.append(json_issue)

    output['overall_risk'] = overall_risk
    output['num_issues'] = len(results)
    output['issues'] = results_to_print

    if print_json:
        print(json.dumps(output, indent=4, sort_keys=True))

    if (thresholds.fail_if_issue_risk_over > 0 and max_issue_risk_found > thresholds.fail_if_issue_risk_over):
        print("Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is " + str(
            max_issue_risk_found) + "].")
        sys.exit(1)

    if (thresholds.fail_if_risk_over > 0 and output['overall_risk'] > thresholds.fail_if_risk_over):
        print("Returning failure as fail_if_risk_over threshold has been exceeded [risk is " + str(
            output['overall_risk']) + "].")
        sys.exit(1)

    if (thresholds.fail_if_issues_over > 0 and output['num_issues'] > thresholds.fail_if_issues_over):
        print("Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is " + str(
            output['num_issues']) + "].")
        sys.exit(1)

    if (thresholds.fail_if_CVSS_over > 0 and max_cvss_found > thresholds.fail_if_CVSS_over):
        print("Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is " + str(
            max_cvss_found) + "].")
        sys.exit(1)


def run_app_stats(host, application_name, token, print_json, thresholds):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting applications and versions.  Code [" + str(
            StatusResponse.status_code) + "]")
        sys.exit(2)

    applications_info = {}

    try:
        applications_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting applications and versions.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    version_infos = []
    application_id = ""
    
    results: list = []
    results.append(applications_info)
    
    for content in results:

        for application in content['content']:
    
            if 'name' in application:
    
                if application['name'] == application_name:
    
                    application_id = application['id']
    
                    # Now that we're in the right record for the application, for each version, retrieve the lists of reports
                    if 'versions' in application:
    
                        for version in application['versions']:
    
                            this_version_info = version_info()
    
                            if 'name' in version:
                                this_version_info.name = version['name']
                                this_version_info.id = version['id']
    
                                version_infos.append(this_version_info)

    num_vulns = 0
    aggregate_risk = 0
    aggregate_issue_titles = []

    # iterate through versions
    for version in version_infos:

        reports = get_reports_list(host, application_id, version.id, token, print_json)

        latest_report_info = get_report_info(host, application_id, version.id, token, reports, -1, print_json)

        latest_report_issues = build_and_print_report_issues(latest_report_info, "Latest", True)

        for latest_iss in latest_report_issues:
            aggregate_risk = aggregate_risk + latest_iss.total_cost

            # latest_report_titles.append(latest_iss.title)

            num_vulns += 1

    if print_json:
        output = {}
        output['total_vulnerabilities'] = num_vulns
        output['aggregate_risk'] = aggregate_risk

        print(json.dumps(output, indent=4, sort_keys=True))
    else:
        print("total num_vuls [" + str(num_vulns) + "]")
        print("total aggregate_risk [" + str(aggregate_risk) + "]")

    # run thresholds
    if (thresholds.fail_if_risk_over > 0 and aggregate_risk > thresholds.fail_if_risk_over):
        print(
            "Returning failure as fail_if_risk_over threshold has been exceeded [application aggregate risk is " + str(
                aggregate_risk) + "].")
        sys.exit(1)

    if (thresholds.fail_if_issues_over > 0 and num_vulns > thresholds.fail_if_issues_over):
        print(
            "Returning failure as fail_if_issues_over threshold has been exceeded [application number of issues is " + str(
                num_vulns) + "].")
        sys.exit(1)


def run_compare_latest_results(host, application, version, token, print_json, thresholds):
    reports = get_reports_list(host, application, version, token, print_json)

    if len(reports) < 2:
        print("Error, compare_latest_results called with less than 2 reports.  Unable to compare.")
        sys.exit(2)

    latest_report_info = get_report_info(host, application, version, token, reports, -1, print_json)

    penultumate_report_info = get_report_info(host, application, version, token, reports, -2, print_json)

    compare_report_infos(latest_report_info, penultumate_report_info, print_json, thresholds)


def run_test_and_compare(host, application, version, token, print_json, thresholds):
    # First run a new scan in blocking mode (so we can check the results afterwards
    run_scan_blocking(host, application, version, token, print_json)

    reports = get_reports_list(host, application, version, token, print_json)

    latest_report_info = get_report_info(host, application, version, token, reports, -1, print_json)

    penultumate_report_info = get_report_info(host, application, version, token, reports, -2, print_json)

    compare_report_infos(latest_report_info, penultumate_report_info, print_json, thresholds)


# Runs a scan and waits until it's completed.
def run_scan_blocking(host, application, version, token, print_json):
    if not print_json:
        print("Running blocking scan")

    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    # Build API URL
    # Kick off a scan
    ScanURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/scan"

    # Run scan
    if not print_json:
        print("Kicking off the scan")

    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print("Exception running scan\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:

        # If you kick off a scan for a version when one is already running, it'll return 400 with a body saying "Scan already running"
        if StatusResponse.status_code == 400 and StatusResponse.text == "Scan already running":
            if not print_json:
                print("Got a 'Scan already running' response, will wait for that scan to finish")
        else:
            # Something went wrong, maybe server not up, maybe auth wrong
            print("Non 200 status code returned when running scan.  Code [" + str(StatusResponse.status_code) + "]")
            sys.exit(2)

    if not print_json:
        print("Scan running")

    #wait_for_scan_to_finish(version)
    wait_for_scan_to_finish(host, token, print_json, version)


# Runs a scan and moves on with it's life.
def run_scan(host, application, version, token, print_json):
    if not print_json:
        print("Running non-blocking scan")

    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    ##### Kick off a scan
    ScanURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/scan"

    # Run scan
    if not print_json:
        print("Kicking off the scan")

    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print("Exception running scan\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:

        # If you kick off a scan for a version when one is already running, it'll return 400 with a body saying "Scan already running"
        if StatusResponse.status_code == 400 and StatusResponse.text == "Scan already running":
            if not print_json:
                print("Got a 'Scan already running' response, nothing to do here")
        else:
            # Something went wrong, maybe server not up, maybe auth wrong
            print("Non 200 status code returned when running scan.  Code [" + str(StatusResponse.status_code) + "]")
            sys.exit(2)

    if not print_json:
        print("Scan running, this is non-blocking mode so now exiting.")


def get_reports_list(host, application, version, token, print_json):
    if not print_json:
        print("Getting list of reports for this pipeline")

    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    #### Get the latest report Id for the app & version

    GetVersionReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version

    try:
        StatusResponse = s.request("Get", GetVersionReportsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting version reports\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting version reports.  Code [" + str(
            StatusResponse.status_code) + "]")
        sys.exit(2)

    version_info = {}

    try:
        version_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when checking for version reports.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    reports_dict = []

    class report_obj:
        id = ""
        vulncount = 0
        tools = ""

    if 'reports' in version_info:
        for report in version_info['reports']:

            this_report = report_obj()

            if 'id' in report:
                this_report.id = report['id']

            if 'vulnerabilityCount' in report:
                this_report.vulncount = report['vulnerabilityCount']

            reports_dict.append(this_report)

    return reports_dict


def get_report_info(host, application, version, token, reports_dict, index, print_json):
    if not print_json:
        print("Getting information on this report")

    # Just wait a few seconds for the background thread to update the report (encase the scan has *just* finished)
    time.sleep(10)

    # Get the report id for the scan
    try:
        latest_report_handle = reports_dict[index]  #
    except IndexError:
        print(
            "Error obtaining handle to report.  Are you examining a latest report without any reports existing?  Or are you attempting to compare reports have have less than two reports?")
        exit(2)

    report_info = get_reports_dict(host, application, version, token, latest_report_handle)

    # Return dict which is the latest report
    return report_info


def get_latest_report_info(host, application, version, token, reports_dict, print_json):
    if not print_json:
        print("Getting information on this report")

    if len(reports_dict) < 1:
        print("Error: no reports found.")
        sys.exit(2)

    # Get the report id for the scan
    latest_report_handle = reports_dict[-1]  # get the latest report

    report_info = {}

    report_info = get_reports_dict(host, application, version, token, latest_report_handle)

    # Return dict which is the latest report
    return report_info


def build_and_print_report_issues(report_info, descriptor, print_json):
    if not print_json:
        print("\n=== Listing issues in " + descriptor + " report =======================")

    report_issues = []

    # Print some info about the latest scan
    for reported_issue in report_info:

        this_issue = issue_info()

        if 'falsePositive' in reported_issue:
            if reported_issue['falsePositive'] is True:
                # print ("False positive being ignored\n")
                continue

        if 'title' in reported_issue:
            this_issue.title = reported_issue['title']

        if 'affectedURL' in reported_issue:
            this_issue.affectedURL = reported_issue['affectedURL']

        if 'summary' in reported_issue:
            this_issue.summary = reported_issue['summary']

        if 'tool' in reported_issue:
            this_issue.tool = reported_issue['tool']['title']

        if 'totalCost' in reported_issue:
            this_issue.total_cost = reported_issue['totalCost']

        if 'vulnerabilitySeverity' in reported_issue:
            this_issue.severity = reported_issue['vulnerabilitySeverity']

        if 'explanation' in reported_issue:
            this_issue.explanation = reported_issue['explanation']

        if 'recommendation' in reported_issue:
            this_issue.recommendation = reported_issue['recommendation']

        if 'vulnerabilityDefinition' in reported_issue:
            try:
                this_issue.CVSS = reported_issue['vulnerabilityDefinition']['standards'][0]['description'] + " : " + \
                                  reported_issue['vulnerabilityDefinition']['standards'][0]['title']
                this_issue.CVSS_value = float(reported_issue['vulnerabilityDefinition']['standards'][0]['description'])
            except IndexError:
                this_issue.CVSS_value = 0.0
                this_issue.CVSS = "CVSS not set"

        report_issues.append(this_issue)

    total_risk = 0

    for iss in report_issues:
        if not print_json:
            print("\nIssue [" + iss.title + "] from tool [" + iss.tool + "]")
            print(" - Resource affected [" + iss.affectedURL + "]")
            print(" - Summary [" + iss.summary + "]")
            print(" - Detail [" + iss.explanation + "]")
            print(" - Recommendation [" + iss.recommendation + "]")
            print(" - CVSS [" + iss.CVSS + "]")
            print(" - Risk [$" + str(f'{iss.total_cost:,}') + "]\n")
        total_risk = total_risk + iss.total_cost

    if not print_json:
        print("\n" + descriptor + " security toolkit run:")
        print("    Total risk:                   = $" + str(f'{total_risk:,}'))
        print("    Total issues:                 = " + str(len(report_issues)))
        print("\n==============================================\n")

    return report_issues


def get_reports_dict(host, application, version, token, report):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetLatestReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/reports/" + report.id + "/vulnerabilities"

    try:
        StatusResponse = s.request("Get", GetLatestReportsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting latest reports\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting latest report.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    latest_report_info = {}

    try:
        latest_report_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting latest report.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    return latest_report_info


def compare_report_infos(latest_report_info, penultumate_report_info, print_json, thresholds):
    if not print_json:
        print("Comparing the latest scan report with the previous one")

    latest_report_issues = build_and_print_report_issues(latest_report_info, "Latest", True)  
    previous_report_issues = build_and_print_report_issues(penultumate_report_info, "Previous", True)

    latest_risk = 0
    previous_risk = 0

    latest_report_titles = []
    penultumate_report_titles = []

    for latest_iss in latest_report_issues:
        latest_risk = latest_risk + latest_iss.total_cost
        latest_report_titles.append(latest_iss.title)

    for prev_iss in previous_report_issues:
        previous_risk = previous_risk + prev_iss.total_cost
        penultumate_report_titles.append(prev_iss.title)

    results = {}

    if previous_risk == latest_risk:
        if not print_json:
            print("\nNo change in risk levels since last check\n")
        results['risk_increase'] = 0
        results['risk_decrease'] = 0
        results['risk_increase_percentage'] = 0
        results['risk_decrease_percentage'] = 0
    elif previous_risk > latest_risk:
        reduced = previous_risk - latest_risk

        if not print_json:
            print("\n    Risk level has REDUCED by       $" + str(f'{reduced:,}'))

        # About to calculate risk % changes, but be careful encase 'latest_risk' is 0
        if latest_risk == 0:
            reduced_percentage = 100
        else:
            reduced_percentage = (100 - (100 / previous_risk) * latest_risk)

        if not print_json:
            print("    Risk level has REDUCED by       " + str(reduced_percentage)[0:4] + "%\n")

        results['risk_increase'] = 0
        results['risk_decrease'] = reduced
        results['risk_increase_percentage'] = 0
        results['risk_decrease_percentage'] = reduced_percentage
    else:
        increased = latest_risk - previous_risk
        if not print_json:
            print("\n    Risk level has INCREASED by    $" + str(f'{increased:,}'))

        # About to calculate risk % changes, but be careful encase 'previous_risk' was 0 and we get an exception
        try:
            increased_percentage = (((100 / previous_risk) * latest_risk) - 100)
        except ZeroDivisionError:
            increased_percentage = latest_risk * 100

        if not print_json:
            print("    Risk level has INCREASED by     " + str(increased_percentage)[0:4] + "%\n")

        results['risk_increase'] = increased
        results['risk_decrease'] = 0
        results['risk_increase_percentage'] = increased_percentage
        results['risk_decrease_percentage'] = 0

    if len(latest_report_issues) == len(previous_report_issues):
        if not print_json:
            print("No change in number of issues since last check\n")
        results['num_increase'] = 0
        results['num_decrease'] = 0
        results['num_increase_percentage'] = 0
        results['num_decrease_percentage'] = 0
    elif len(latest_report_issues) < len(previous_report_issues):
        if not print_json:
            print("    Number of issues has REDUCED by   " + str(
                (len(previous_report_issues) - len(latest_report_issues))))
        reduced_issue_percentage = (100 - (100 / len(previous_report_issues)) * len(latest_report_issues))
        if not print_json:
            print("    Number of issues has REDUCED by   " + str(reduced_issue_percentage)[0:4] + "%\n")

        results['num_increase'] = 0
        results['num_decrease'] = len(previous_report_issues) - len(latest_report_issues)
        results['num_increase_percentage'] = 0
        results['num_decrease_percentage'] = reduced_issue_percentage
    else:
        if not print_json:
            print("    Number of issues has INCREASED by   " + str(
                (len(latest_report_issues) - len(previous_report_issues))))
        increased_issue_percentage = (((100 / len(previous_report_issues)) * len(latest_report_issues)) - 100)
        if not print_json:
            print("    Number of issues has INCREASED by   " + str(increased_issue_percentage)[0:4] + "%\n")

        results['num_increase'] = len(latest_report_issues) - len(previous_report_issues)
        results['num_decrease'] = 0
        results['num_increase_percentage'] = increased_issue_percentage
        results['num_decrease_percentage'] = 0

    new_issues = []
    json_issues_dict = []

    ### penultumate_report_titles is set, so is latest_report_titles, so compare them
    new_risk = 0
    max_cvss_found = 0.0
    max_issue_risk_found = 0

    for latest_title in latest_report_titles:

        if latest_title in penultumate_report_titles:
            # This issue was there before, not new
            # Note this comparison needs to be improved, as it's likely to have duplicate titles - need to add codeline/reference
            continue
        else:
            # It's a new issue
            if not print_json:
                print("\nNEW ISSUE in this toolkit run:")

            json_issue = {}

            for i in latest_report_issues:
                if i.title == latest_title:
                    if not print_json:
                        print("        " + i.title + ": tool [" + i.tool + "]:     Risk $" + str(
                            f'{i.total_cost:,}') + "")
                        print("        CVSS : " + i.CVSS)
                    new_risk = new_risk + i.total_cost

                    json_issue['title'] = i.title
                    json_issue['tool'] = i.tool
                    json_issue['risk'] = i.total_cost
                    json_issue['cvss'] = i.CVSS
                    json_issue['summary'] = i.summary
                    json_issue['severity'] = i.severity
                    json_issue['explanation'] = i.explanation
                    json_issue['recommendation'] = i.recommendation

                    if i.CVSS_value > max_cvss_found:
                        max_cvss_found = i.CVSS_value

                    if i.total_cost > max_issue_risk_found:
                        max_issue_risk_found = i.total_cost

            new_issues.append(i)
            json_issues_dict.append(json_issue)

    if new_risk != 0:
        if not print_json:
            print("\n    New risk in this tookit run    = $" + str(f'{new_risk:,}'))

    for pen_title in penultumate_report_titles:

        if pen_title in latest_report_titles:
            # This issue is in both, don't mention
            continue
        else:
            if not print_json:
                print("\nISSUE FIXED before this toolkit run:")

                for i in previous_report_issues:
                    if i.title == pen_title:
                        print("        " + i.title + ": tool [" + i.tool + "]:     Risk $" + str(
                            f'{i.total_cost:,}') + "")
                        print("        CVSS : " + i.CVSS)

    results['new_issues'] = json_issues_dict

    if print_json:
        print(json.dumps(results, indent=4, sort_keys=True))

    if (thresholds.fail_if_issue_risk_over > 0 and max_issue_risk_found > thresholds.fail_if_issue_risk_over):
        print("Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is " + str(
            max_issue_risk_found) + "].")
        sys.exit(1)

    if (thresholds.fail_if_risk_over > 0 and latest_risk > thresholds.fail_if_risk_over):
        print("Returning failure as fail_if_risk_over threshold has been exceeded [risk is " + str(latest_risk) + "].")
        sys.exit(1)

    if (thresholds.fail_if_issues_over > 0 and len(latest_report_issues) > thresholds.fail_if_issues_over):
        print("Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is " + str(
            len(latest_report_issues)) + "].")
        sys.exit(1)

    if (thresholds.fail_if_CVSS_over > 0 and max_cvss_found > thresholds.fail_if_CVSS_over):
        print("Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is " + str(
            max_cvss_found) + "].")
        sys.exit(1)

    if (thresholds.fail_if_risk_change_over > 0 and new_risk > thresholds.fail_if_risk_change_over):
        print("Returning failure as fail_if_risk_change_over threshold has been exceeded [new risk found is " + str(
            new_risk) + "].")
        sys.exit(1)

    if (thresholds.fail_if_issues_change_over > 0 and len(new_issues) > thresholds.fail_if_issues_change_over):
        print("Returning failure as fail_if_issues_change_over threshold has been exceeded [new issues found is " + str(
            len(new_issues)) + "].")
        sys.exit(1)


def map_app_name_to_id(host, application_name, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting applications.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    try:
        application_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting applications.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    application_id = ""
    
    results: list = []
    results.append(application_info)
    
    for content in results:

        for application in content['content']:
    
            if 'name' in application:
    
                if application['name'] == application_name:
                    # We have found the application, record the GUID
                    application_id = application['id']
                    if not print_json:
                        print("Application ID found for [" + application_name + "]: " + application_id)
    
                    break

    if application_id == "":
        # we didn't find app id, so return a failure
        print("Failed to find app id: application name [" + application_name + "], id [" + application_id + "]")
        print("Failing")
        sys.exit(2)

    return application_id


def map_app_name_and_version_to_ids(host, application_name, version_name, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting applications and versions.  Code [" + str(
            StatusResponse.status_code) + "]")
        sys.exit(2)

    application_and_versions_info = {}

    try:
        application_and_versions_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting applications and versions.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    application_id = ""
    version_id = ""
    
    results: list = []
    results.append(application_and_versions_info)
    
    for content in results:

        for application in content['content']:
    
            if 'name' in application:
    
                if application['name'] == application_name:
                    # We have found the application, record the GUID
                    application_id = application['id']
                    if not print_json:
                        print("Application ID found for [" + application_name + "]: " + application_id)
    
                    # Now that we're in the right record for the application, find the version name
                    if 'versions' in application:
    
                        for version in application['versions']:
                            if 'name' in version:
    
                                if version['name'] == version_name:
                                    # We're in the right version, record the GUID
                                    version_id = version['id']
                                    if not print_json:
                                        print("Version ID found for [" + version_name + "]: " + version_id)
    
                                    break

    # check ""
    if application_id == "" or version_id == "":
        # we didn't find one of the ids, so return a failure
        print(
            "Failed to find one or both ids: application name [" + application_name + "], id [" + application_id + "], version name [" + version_name + "] id [" + version_id + "]")
        sys.exit(2)

    results = ids()
    results.application_id = application_id
    results.version_id = version_id

    if not print_json:
        print(
            "Mapped names to ids: application name [" + application_name + "], id [" + results.application_id + "], version name [" + version_name + "] id [" + results.version_id + "]")

    return results


def run_map_app_name_to_id(host, application_name, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting applications and versions.  Code [" + str(
            StatusResponse.status_code) + "]")
        sys.exit(2)

    application_and_versions_info = {}

    try:
        application_and_versions_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting applications and versions.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    application_id = ""
    version_id = ""
    
    results: list = []
    results.append(application_and_versions_info)
    
    for content in results:

        for application in content['content']:
    
            if 'name' in application:
    
                if application['name'] == application_name:
                    # We have found the application, record the GUID
                    application_id = application['id']
                    if not print_json:
                        print("Application ID found for [" + application_name + "]: " + application_id)

    # check ""
    if application_id == "":
        # we didn't find one of the ids, so return a failure
        print("Failed to find id for application name [" + application_name + "], id [" + application_id + "]")
        sys.exit(2)

    if not print_json:
        print("Mapped name to id: application name [" + application_name + "], id [" + application_id + "]")

    return application_id


def run_check_for_existing_version(host, application_name, version_name, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting applications and versions.  Code [" + str(
            StatusResponse.status_code) + "]")
        sys.exit(2)

    application_and_versions_info = {}

    try:
        application_and_versions_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting applications and versions.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    version_id = ""
    
    results: list = []
    results.append(application_and_versions_info)
    
    for content in results:
        
        for application in content['content']:

            if 'name' in application:
    
                if application['name'] == application_name:
                    # We have found the application
    
                    if not print_json:
                        print("Application found for [" + application_name + "]")
    
                    # Now that we're in the right record for the application, find the version name
                    if 'versions' in application:
    
                        for version in application['versions']:
                            if 'name' in version:
    
                                if version['name'] == version_name:
                                    # We're in the right version, record the GUID
                                    version_id = version['id']
                                    if not print_json:
                                        print("Version ID found for [" + version_name + "]: " + version_id)
    
                                    break

    if not print_json:
        print("Mapped names to id: version name [" + version_name + "] id [" + version_id + "]")

    return version_id


def run_create_version_with_credentials(host, application, version_name, token, print_json, sast_git, sast_username,
                                        sast_token, tools_to_add):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    AddVersionURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions"

    payload = '{"name":"' + version_name + '","forceCookies":false,"roles":[],"webPageList":[],"tools":[],"reports":[],"actions":[],"scmConfiguration":{"useUpload":false,"authenticationType":"USER_PASS","address":"' + sast_git + '","identity":"' + sast_username + '","secret":"' + sast_token + '"}}'

    payload_json = json.loads(payload)

    payload_json['tools'] = tools_to_add

    # print( "About to send " + json.dumps (payload_json))

    try:
        StatusResponse = s.request("POST", AddVersionURL, json=payload_json)
    except requests.exceptions.RequestException as err:
        print("Exception adding version\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 201:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 201 status code returned when adding version.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    new_version_info = {}

    try:
        new_version_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when adding new version.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    version_id = ""

    if 'id' in new_version_info:
        version_id = new_version_info['id']

        if not print_json:
            print("New version created: name [" + version_name + "], id [" + version_id + "]")

    else:
        print("Error, no version id returned when creating new version")
        exit(2)

    return version_id


def run_create_version(host, application, version_name, token, print_json, sast_git, tools_to_add):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    AddVersionURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions"

    payload = '{"name":"' + version_name + '","forceCookies":false,"roles":[],"webPageList":[],"tools":[],"reports":[],"actions":[],"scmConfiguration":{"useUpload":false,"authenticationType":"UNAUTHENTICATED","address":"' + sast_git + '"}}'

    payload_json = json.loads(payload)

    payload_json['tools'] = tools_to_add

    try:
        StatusResponse = s.request("POST", AddVersionURL, json=payload_json)
    except requests.exceptions.RequestException as err:
        print("Exception adding version\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 201:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 201 status code returned when adding version.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    new_version_info = {}

    try:
        new_version_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when adding new version.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    version_id = ""

    if 'id' in new_version_info:
        version_id = new_version_info['id']

        if not print_json:
            print("New version created: name [" + version_name + "], id [" + version_id + "]")

    else:
        print("Error, no version id returned when creating new version")
        exit(2)

    return version_id


def run_get_verison_info(host, application, version, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetVersionURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version

    try:
        StatusResponse = s.request("Get", GetVersionURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting version\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 201 status code returned when getting version.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    version_info = {}

    try:
        version_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when adding new version.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    return version_info


def run_update_version(host, application, version, token, print_json, version_data, tools_to_add):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    UpdateVersionURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version

    payload_json = version_data

    payload_json['tools'] = tools_to_add

    try:
        StatusResponse = s.request("PUT", UpdateVersionURL, json=payload_json)
    except requests.exceptions.RequestException as err:
        print("Exception updating version\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when updating version.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    if not print_json:
        print("Updated version configuration")


def run_get_tools_details(host, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetToolsURL = host + "SecureDesigner/api/v1/tools"

    try:
        StatusResponse = s.request("Get", GetToolsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting tools\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting tools.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    tools_info = {}

    try:
        tools_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when getting tools.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    return tools_info


def run_map_container_name_to_id(host, connection_name, token, print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    GetConnectionsURL = host + "SecureDesigner/api/v1/connections/"

    try:
        StatusResponse = s.request("Get", GetConnectionsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting connections\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting connections.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit(2)

    connections_info = {}

    try:
        connections_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when extracting connections.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    connection_id = ""

    for connection_config in connections_info:

        if 'toolName' in connection_config:

            if connection_config['toolName'] == connection_name:
                # We have found the connection, record the GUID
                connection_id = connection_config['id']
                if not print_json:
                    print("Connection ID found for [" + connection_name + "]: " + connection_id)

    # check ""
    if connection_id == "":
        # we didn't find one of the ids, so return a failure
        print("Failed to find id for connection name [" + connection_name + "], id [" + connection_id + "]")
        sys.exit(2)

    if not print_json:
        print("Mapped connection name to id: connection name [" + connection_name + "], id [" + connection_id + "]")

    return connection_id


def run_update_container_config(host, application, version, container_image, container_tag, connection_id, token,
                                print_json):
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "" + token
    })

    UpdateVersionContainerURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/container-image"

    if connection_id == "null":
        payload = '{"name":"' + container_image + '","tag":"' + container_tag + '","connectionId":' + connection_id + '}'
    else:
        payload = '{"name":"' + container_image + '","tag":"' + container_tag + '","connectionId":"' + connection_id + '"}'

    payload_json = json.loads(payload)

    try:
        StatusResponse = s.request("PUT", UpdateVersionContainerURL, json=payload_json)
    except requests.exceptions.RequestException as err:
        print("Exception updating version\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when updating container config.  Code [" + str(
            StatusResponse.status_code) + "]")
        sys.exit(2)

    if not print_json:
        print("Updated container configuration")


def run_scan_with_toolkits_and_results(host: str, application: str, version: str, token: str, toolkit_id: str,
                                       print_json: bool, thresholds: FailureThresholds):
    scan_with_toolkit(host, token, application, version, toolkit_id)
    wait_for_scan_to_finish(host, token, print_json, version)
    reports = get_reports_list(host, application, version, token, print_json)
    report_info = get_report_info(host, application, version, token, reports, -1, print_json)
    report_issues = build_and_print_report_issues(report_info, "Latest", print_json)
    print_output_and_check_thresholds(report_issues, print_json, thresholds)

def run_scan_with_toolkits_and_compare(host: str, application: str, version: str, token: str, toolkit_id: str,
                                       print_json: bool, thresholds: FailureThresholds):
    scan_with_toolkit(host, token, application, version, toolkit_id)
    wait_for_scan_to_finish(host, token, print_json, version)
    reports = get_reports_list(host, application, version, token, print_json)
    latest_report_info = get_report_info(host, application, version, token, reports, -1, print_json)
    penultumate_report_info = get_report_info(host, application, version, token, reports, -2, print_json)
    compare_report_infos(latest_report_info, penultumate_report_info, print_json, thresholds)


if __name__ == "__main__":
    _main()
