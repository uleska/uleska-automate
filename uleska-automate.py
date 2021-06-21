import requests
import json
import argparse
import time
import sys

class issue_info:
    title = ""
    tool = ""
    total_cost = 0
    CVSS = ""
    affectedURL = ""
    summary = ""

class ids:
    application_id = ""
    version_id = ""
    


def _main():
    
    #Capture command line arguments
    arguments = sys.argv
    
    #Capture command line arguments
    arg_options = argparse.ArgumentParser(description="Uleska command line interface. To identify the project/pipeline to test you can specify either --application_name and --version_name, or --application and --version (passing GUIDs). (Version 0.2)", )
    arg_options.add_argument('--uleska_host', help="URL to the Uleska host (e.g. https://s1.uleska.com/) (note final / is required)", required=True, type=str)
    arg_options.add_argument('--token', help="String for the authentication token", required=True, type=str)
    
    arg_options.add_argument('--application_id', help="GUID for the application to reference", type=str)
    arg_options.add_argument('--version_id', help="GUID for the application version/pipeline to reference", type=str)
    arg_options.add_argument('--application_name', help="Name for the application to reference", type=str)
    arg_options.add_argument('--version_name', help="Name for the version/pipeline to reference", type=str)
    
    arg_options.add_argument('--test', help="Run tests only for the application and version referenced, do not wait for the results", action="store_true")
    arg_options.add_argument('--test_and_results', help="Run tests for the application and version referenced, and return the results from the last as JSON", action="store_true")
    arg_options.add_argument('--test_and_compare', help="Run tests for the application and version referenced, and return any differences in the results from the last test", action="store_true")
    
    arg_options.add_argument('--latest_results', help="Retrieve the latest test results for application and version referenced", action="store_true")
    arg_options.add_argument('--compare_latest_results', help="Retrieve the latest test results for application and version and compare", action="store_true")
    
    arg_options.add_argument('--get_ids', help="Retrieve GUID for the application_name and version_name supplied", action="store_true")

    #arg_options.add_argument('--add_version', help="Add a new version (pipeline) to the application referenced", action="store_true")

    arg_options.add_argument('--debug', help="Prints debug messages", action="store_true")
    
    
    args = arg_options.parse_args()
    
    host = ""
    application = "" #id
    version = "" #id
    token = ""
    
    test_and_compare = False
    test_and_results = False
    test = False
    latest_results = False
    comapre_latest_results = False
    add_version = False
    get_ids = False
    
    application_name = ""
    version_name = ""
    
    debug = False
    
    #Set debug
    if args.debug:
        debug = True
        print("Debug enabled")
    
    
    #Grab the host from the command line arguments
    if args.uleska_host is not None:
        host = args.uleska_host
        
        if debug:
            print("Host: " + host)
            
    #Grab the application id from the command line arguments
    if args.application_id is not None:
        application = args.application_id
        
        if debug:
            print("Application id: " + application)
    
    #Grab the version from the command line arguments
    if args.version_id is not None:
        version = args.version_id
        
        if debug:
            print("Version id: " + version)
    
    #Grab the token from the command line arguments
    if args.token is not None:
        token = args.token
        
        if debug:
            print("Token: " + token)
    
    #Set test_and_compare
    if args.test_and_compare:
        test_and_compare = True
        
        if debug:
            print("test_and_compare enabled")
    
    #Set test_and_results
    if args.test_and_results:
        test_and_results = True
        
        if debug:
            print("test_and_results enabled")
    
    #Set test
    if args.test:
        test = True
        
        if debug:
            print("test enabled")
    
    #Set latest_results
    if args.latest_results:
        latest_results = True
        
        if debug:
            print("latest_results enabled")
    
    #Set compare_latest_results
    if args.compare_latest_results:
        compare_latest_results = True
        
        if debug:
            print("compare_latest_results enabled")
    
    #Set add_version
    #if args.add_version:
    #    add_version = True
        
    #    if debug:
    #        print("add_version enabled")
            
    #Set get_ids
    if args.get_ids:
        get_ids = True
        
        if debug:
            print("get_ids enabled")
    
    #Grab the application_name from the command line arguments
    if args.application_name is not None:
        application_name = args.application_name
            
        if debug:
            print("Application name: " + application_name)  
    
    #Grab the version_name from the command line arguments
    if args.version_name is not None:
        version_name = args.version_name
            
        if debug:
            print("Version name: " + version_name)    
                
    
    if application_name != "" or version_name != "":
        print("Application or version name passed, looking up ids...")
        #results = ids()
        results = map_app_name_and_version_to_ids(host, application_name, version_name, token)
    
        application = results.application_id
        version = results.version_id
        
    
    
    
    #Args retrieved, now decide what we're doing
    if get_ids:
        # No action as map_app_name_and_version_to_ids will have already returned the ids
        pass
    elif test_and_compare:
        run_test_and_compare(host, application, version, token)
    elif test_and_results:
        run_test_and_results(host, application, version, token)
    elif test:
        run_scan(host, application, version, token)
    elif latest_results:
        run_latest_results(host, application, version, token)
    elif compare_latest_results:
        run_compare_latest_results(host, application, version, token)
    elif add_version:
        run_add_version(host, application, version, token, version_name)
    else:
        print("No recognised function specified.")
        


def run_test_and_results(host, application, version, token):
    
    # First run a new scan in blocking mode (so we can check the results afterwards
    run_scan_blocking(host, application, version, token)
    
    reports = get_reports_list(host, application, version, token)

    report_info = get_report_info(host, application, version, token, reports, -1)
    
    print_report_info(report_info, "Latest")
    



def run_latest_results(host, application, version, token):
    
    reports = get_reports_list(host, application, version, token)

    report_info = get_report_info(host, application, version, token, reports, -1)
    
    print_report_info(report_info, "Latest")
    
    

def run_compare_latest_results(host, application, version, token):
    
    reports = get_reports_list(host, application, version, token)

    latest_report_info = get_report_info(host, application, version, token, reports, -1)
    
    penultumate_report_info = get_report_info(host, application, version, token, reports, -2)
    
    compare_report_infos(latest_report_info, penultumate_report_info)
    


def run_test_and_compare(host, application, version, token):
    
    # First run a new scan in blocking mode (so we can check the results afterwards
    run_scan_blocking(host, application, version, token)
    
    reports = get_reports_list(host, application, version, token)

    latest_report_info = get_report_info(host, application, version, token, reports, -1)
    
    penultumate_report_info = get_report_info(host, application, version, token, reports, -2)
    
    compare_report_infos(latest_report_info, penultumate_report_info)
    


# Runs a scan and waits until it's completed.  
def run_scan_blocking(host, application, version, token):
    
    print ("Running blocking scan")
    
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "Bearer " + token
        })

    #Build API URL
    # Kick off a scan
    ScanURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/scan"

    #Run scan
    print("Kicking off the scan")
    
    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print ("Exception running scan\n" + str(err))
        sys.exit()
        
    if StatusResponse.status_code != 200:
        #Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when running scan.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit()
    
    print("Scan running")
    
    
    #### Scan should be running, run check scans to see if it's still running
    scanfinished = False

    CheckScanURL = host + "SecureDesigner/api/v1/scans"

    while scanfinished is False:
        
        try:
            StatusResponse = s.request("Get", CheckScanURL)
        except requests.exceptions.RequestException as err:
            print ("Exception checking for running scan\n" + str(err))
            sys.exit()
            
        if StatusResponse.status_code != 200:
            #Something went wrong, maybe server not up, maybe auth wrong
            print("Non 200 status code returned when checking for running scan.  Code [" + str(StatusResponse.status_code) + "]")
            sys.exit()
        
        #### we have a response, check to see if this scan is still running.  Note there could be multiple scans running
        running_scans_json = {}
        
        try:
            running_scans_json = json.loads(StatusResponse.text)
        except json.JSONDecodeError as jex:
            print ("Invalid JSON when checking for running scans.  Exception: [" + str(jex) + "]")
            sys.exit()
        
        if len(running_scans_json) == 0:
            #### if there's no scans running, then it must have finished
            print ("No more scans running\n")
            scanfinished = True
            break
        
        versions_running = []

        for scan in running_scans_json:
            if 'versionId' in scan:

                versions_running.append(scan['versionId'])

            else:
                print ("No versionId in the scan\n")

        print("DEBUG: Versions running = " + str(versions_running) )

        if version in versions_running:
            print ("Our Toolkit " + version + " is still running, waiting...\n")
            time.sleep(10)
        else:
            print ("Our Toolkit " + version + " has completed\n")
            scanfinished = True
            break

                
                

# Runs a scan and moves on with it's life.  
def run_scan(host, application, version, token):
    
    print ("Running non-blocking scan")
    
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "Bearer " + token
        })

    #Build API URL
    #host = "https://uleska-live-one.uleska.com/"

    ##### Kick off a scan
    ScanURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/scan"

    #Run scan
    print("Kicking off the scan")
    
    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print ("Exception running scan\n" + str(err))
        sys.exit()
        
    if StatusResponse.status_code != 200:
        #Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when running scan.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit()
    
    print("Scan running, this is non-blocking mode so now exiting.")

                
                
                
                
                
def get_reports_list(host, application, version, token):
    
    print ("Getting list of reports for this pipeline")
    
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "Bearer " + token
        })
    

    #### Get the latest report Id for the app & version
    
    GetVersionReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version
    
    try:
        StatusResponse = s.request("Get", GetVersionReportsURL)
    except requests.exceptions.RequestException as err:
        print ("Exception getting version reports\n" + str(err))
        sys.exit()
        
    if StatusResponse.status_code != 200:
        #Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting version reports.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit()


    version_info = {}
    
    try:
        version_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print ("Invalid JSON when checking for version reports.  Exception: [" + str(jex) + "]")
        sys.exit()
    

    reports_dict = []
    
    class report_obj:
        id = ""
        vulncount = 0
        tools = ""
    
    
    if 'reports' in version_info:
        for report in version_info['reports']:
            #print ("Report is as follows \n\n" + str(report))
            this_report = report_obj()
            
            if 'id' in report:
                this_report.id = report['id']
            
            if 'vulnerabilityCount' in report:
                this_report.vulncount = report['vulnerabilityCount']
            
            reports_dict.append(this_report)
            
    return reports_dict
        
        
        

def get_report_info(host, application, version, token, reports_dict, index):        
    
    print ("Getting information on this report")
    
    # Just wait a few seconds for the background thread to update the report (encase the scan has *just* finished)  
    time.sleep(5)
    
    # Get the report id for the scan
    latest_report_handle = reports_dict[index] # -1
    
    report_info = {}
    
    report_info = get_reports_dict(host, application, version, token, latest_report_handle)
    
    # Return dict which is the latest report
    return report_info
    




def print_report_info(report_info, descriptor):
    
    print ("\n=== Listing issues in " + descriptor + " report =======================")
    
    report_issues = []
    
    # Print some info about the latest scan 
    for reported_issue in report_info:
        
        this_issue = issue_info()
        
        if 'falsePositive' in reported_issue:
            if reported_issue['falsePositive'] is True:
                #print ("False positive being ignored\n")
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
            
        if 'vulnerabilityDefinition' in reported_issue:
            this_issue.CVSS = reported_issue['vulnerabilityDefinition']['standards'][0]['description'] + " : " + reported_issue['vulnerabilityDefinition']['standards'][0]['title']
        
        report_issues.append(this_issue)
            
    total_risk = 0
    
    for iss in report_issues:
        print ("\nIssue [" + iss.title + "] from tool [" + iss.tool + "]")
        print ("Resource affected [" + iss.affectedURL + "]")
        print ("Summary [" + iss.summary + "]")
        print ("Cost [$" + str( f'{iss.total_cost:,}') + "]\n")
        total_risk = total_risk + iss.total_cost
    
    
    print ("\n" + descriptor + " security toolkit run:")
    print ("    Total risk:                   = $" + str( f'{total_risk:,}' ))
    print ("    Total issues:                 = " + str( len( report_issues ) ) )
    print ("\n==============================================\n")
    
    return report_issues








def get_reports_dict(host, application, version, token, report):
    
   
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "Bearer " + token
        })
    
    GetLatestReportsURL = host + "SecureDesigner/api/v1/applications/" + application + "/versions/" + version + "/reports/" + report.id + "/vulnerabilities"
    
          
    try:
        StatusResponse = s.request("Get", GetLatestReportsURL)
    except requests.exceptions.RequestException as err:
        print ("Exception getting latest reports\n" + str(err))
        sys.exit()
        
    if StatusResponse.status_code != 200:
        #Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting latest report.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit()
    
    
    latest_report_info = {}
    
    #latest_report_issues = []
    #latest_report_titles = []

    try:
        latest_report_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print ("Invalid JSON when extracting latest report.  Exception: [" + str(jex) + "]")
        sys.exit()

    return latest_report_info





def compare_report_infos(latest_report_info, penultumate_report_info):
    
    print ("Comparing the latest scan report with the previous one")
    
    latest_report_issues = print_report_info(latest_report_info, "Latest")
    previous_report_issues = print_report_info(penultumate_report_info, "Previous")
    
    latest_risk = 0
    previous_risk = 0
    
    latest_report_titles = []
    penultumate_report_titles = []
    
    for latest_iss in latest_report_issues:
        #print ("Latest Reported Issue with title [" + iss.title + "] and tool [" + iss.tool + "] and cost [" + str(iss.total_cost) + "]" )
        latest_risk = latest_risk + latest_iss.total_cost
        #latest_report_titles.append(latest_iss['title'])
        latest_report_titles.append(latest_iss.title)
    
    for prev_iss in previous_report_issues:
        #print ("Latest Reported Issue with title [" + iss.title + "] and tool [" + iss.tool + "] and cost [" + str(iss.total_cost) + "]" )
        previous_risk = previous_risk + prev_iss.total_cost
        #penultumate_report_titles.append(prev_iss['title'])
        penultumate_report_titles.append(prev_iss.title)
    
    
    if previous_risk == latest_risk:
        print ("\nNo change in risk levels since last check\n")
    elif previous_risk > latest_risk:
        reduced = previous_risk - latest_risk
        print ("\n    Risk level has REDUCED by       $" + str( f'{reduced:,}' ))
        reduced_percentage = ( 100 - ( 100 / previous_risk ) * latest_risk )
        print ("    Risk level has REDUCED by       " + str( reduced_percentage )[0:4] + "%\n")
    else:
        increased = latest_risk - previous_risk
        print ("\n    Risk level has INCREASED by    $" + str( f'{increased:,}' ))
        increased_percentage = ( ( ( 100 / previous_risk  ) * latest_risk ) - 100)
        print ("    Risk level has INCREASED by     " + str( increased_percentage )[0:4] + "%\n")
    
    
    if len(latest_report_issues) == len(previous_report_issues):
        print ("No change in number of issues since last check\n")
        return
    elif len (latest_report_issues) < len(previous_report_issues):
        print("    Number of issues has REDUCED by   " + str ( ( len (previous_report_issues) - len(latest_report_issues) ) ) )
        reduced_issue_percentage = ( 100 - ( 100 / len(previous_report_issues) ) * len (latest_report_issues) )
        print ("    Number of issues has REDUCED by   " + str( reduced_issue_percentage )[0:4] + "%\n")
    else:
        print("    Number of issues has INCREASED by   " + str( ( len(latest_report_issues) - len(previous_report_issues) ) ) )
        increased_issue_percentage = ( ( ( 100 / len (previous_report_issues) ) * len(latest_report_issues) ) - 100 )
        print ("    Number of issues has INCREASED by   " + str( increased_issue_percentage )[0:4] + "%\n")
    
    
    ### penultumate_report_titles is set, so is latest_report_titles, how do I compare them?
    new_risk = 0
    for latest_title in latest_report_titles:
           
        if latest_title in penultumate_report_titles:
            # This issue was there before, not new
            # Note this comparison needs to be improved, as it's likely to have duplicate titles - need to add codeline/reference
            continue
        else:
            # It's a new issue
            print ("\nNEW ISSUE in this toolkit run:")
            
            for i in latest_report_issues:
                if i.title == latest_title:
                    print ("        " + i.title + ": tool [" + i.tool + "]:     Risk $" + str( f'{i.total_cost:,}' ) + "" )
                    print ("        CVSS : " + i.CVSS )
                    new_risk = new_risk + i.total_cost
    
    if new_risk is not 0:
        print ("\n    New risk in this tookit run    = $" + str( f'{new_risk:,}'  ) )
                    
    
    for pen_title in penultumate_report_titles:
        
        if pen_title in latest_report_titles:
            # This issue is in both, don't mention
            continue
        else:
            print ("\nISSUE FIXED before this toolkit run:")
            
            for i in previous_report_issues:
                if i.title == pen_title:
                    print ("        " + i.title + ": tool [" + i.tool + "]:     Risk $" + str( f'{i.total_cost:,}' ) +"" )
                    print ("        CVSS : " + i.CVSS )
    
    print ("\n")
    



def map_app_name_and_version_to_ids(host, application_name, version_name, token):
    
    s = requests.Session()

    s.headers.update({
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': "Bearer " + token
        })
    
    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"
    
          
    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print ("Exception getting applications and versions\n" + str(err))
        sys.exit()
        
    if StatusResponse.status_code != 200:
        #Something went wrong, maybe server not up, maybe auth wrong
        print("Non 200 status code returned when getting applications and versions.  Code [" + str(StatusResponse.status_code) + "]")
        sys.exit()
    
    
    application_and_versions_info = {}
    

    try:
        application_and_versions_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print ("Invalid JSON when extracting applications and versions.  Exception: [" + str(jex) + "]")
        sys.exit()
    
    
    application_id = ""
    version_id = ""
    
    for application in application_and_versions_info:
        
        if 'name' in application:
            
            if application['name'] == application_name:
                #We have found the application, record the GUID
                application_id = application['id']
                print("Application ID found for [" + application_name +"]: " + application_id)
                
                # Now that we're in the right record for the application, find the version name
                if 'versions' in application:
                    
                                       
                    for version in application['versions']:
                        if 'name' in version:
                            
                            if version['name'] == version_name:
                                #We're in the right version, record the GUID
                                version_id = version['id']
                                print("Version ID found for [" + version_name +"]: " + version_id)
                                
                                break
        
    # check ""
    if application_id == "" or version_id == "":
        # we didn't find one of the ids, so return a failure
        print("Failed to find one or both ids: application name [" + application_name + "], id [" + application_id + "], version name [" + version_name + "] id [" + version_id + "]")
        print("Failing")
        sys.exit()
            
        
    results = ids()
    results.application_id = application_id
    results.version_id = version_id

    print("Mapped names to ids: application name [" + application_name + "], id [" + results.application_id + "], version name [" + version_name + "] id [" + results.version_id + "]")
    
    return results


    
    

if __name__ == "__main__":
    _main()
