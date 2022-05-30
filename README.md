# uleska-automate

Uleska CLI for ease of integration with CI/CD and similar systems

```

 ___  ___  ___       _______   ________  ___  __    ________     
|\  \|\  \|\  \     |\  ___ \ |\   ____\|\  \|\  \ |\   __  \    
\ \  \\\  \ \  \    \ \   __/|\ \  \___|\ \  \/  /|\ \  \|\  \   
 \ \  \\\  \ \  \    \ \  \_|/_\ \_____  \ \   ___  \ \   __  \  
  \ \  \\\  \ \  \____\ \  \_|\ \|____|\  \ \  \\ \  \ \  \ \  \ 
   \ \_______\ \_______\ \_______\____\_\  \ \__\\ \__\ \__\ \__\
    \|_______|\|_______|\|_______|\_________\|__| \|__|\|__|\|__|
                                 \|_________|                    
                                 
                                 
usage: uleska-automate.py [-h] --uleska_host ULESKA_HOST --token TOKEN
                          [--application_id APPLICATION_ID]
                          [--version_id VERSION_ID]
                          [--application_name APPLICATION_NAME]
                          [--version_name VERSION_NAME] [--update_sast]
                          [--sast_git SAST_GIT]
                          [--sast_username SAST_USERNAME]
                          [--sast_token SAST_TOKEN]
                          [--update_container]
                          [--container_image CONTAINER_IMAGE]
                          [--container_tag CONTAINER_TAG]
                          [--container_connection CONTAINER_CONNECTION]
                          [--test] [--test_and_results] [--test_and_compare]
                          [--latest_results] [--compare_latest_results]
                          [--print_json] [--get_ids] [--app_stats]
                          [--fail_if_issue_risk_over FAIL_IF_ISSUE_RISK_OVER]
                          [--fail_if_risk_over FAIL_IF_RISK_OVER]
                          [--fail_if_risk_change_over FAIL_IF_RISK_CHANGE_OVER]
                          [--fail_if_issues_over FAIL_IF_ISSUES_OVER]
                          [--fail_if_issues_change_over FAIL_IF_ISSUES_CHANGE_OVER]
                          [--fail_if_CVSS_over FAIL_IF_CVSS_OVER] [--debug]

Uleska command line interface. To identify the project/pipeline to test you
can specify either --application_name and --version_name, or --application and
--version (passing GUIDs). (Version 0.7)

optional arguments:
  -h, --help            show this help message and exit
  --uleska_host ULESKA_HOST
                        URL to the Uleska host (e.g. https://s1.uleska.com/)
                        (note final / is required)
  --token TOKEN         String for the authentication token
  --application_id APPLICATION_ID
                        GUID for the application to reference
  --version_id VERSION_ID
                        GUID for the application version/pipeline to reference
  --application_name APPLICATION_NAME
                        Name for the application to reference
  --version_name VERSION_NAME
                        Name for the version/pipeline to reference
  --update_sast         Add or update a SAST pipeline. Requires an pre-
                        existing application. See documentation for other
                        settings
  --sast_git SAST_GIT   Git URL for SAST repo. Required with --update_sast.
  --sast_username SAST_USERNAME
                        If repo requires authentication, this is the username
                        to use. Optional with --update_sast.
  --sast_token SAST_TOKEN
                        If repo requires authentication, this is the token
                        value to use. Optional with --update_sast.
  --update_container    Update a container pipeline. Requires an pre-existing
                        application/config. See documentation for other
                        settings
  --container_image CONTAINER_IMAGE
                        Name of image to use. Required with
                        --update_container.
  --container_tag CONTAINER_TAG
                        Tag to use. Required with --update_container.
  --container_connection CONTAINER_CONNECTION
                        Connection name to use for container access. Optional
                        with --update_container. If not included Docker Hub is
                        assumed.
  --test                Run tests only for the application and version
                        referenced, do not wait for the results
  --test_and_results    Run tests for the application and version referenced,
                        and return the results from the last as JSON
  --test_and_compare    Run tests for the application and version referenced,
                        and return any differences in the results from the
                        last test
  --latest_results      Retrieve the latest test results for application and
                        version referenced
  --compare_latest_results
                        Retrieve the latest test results for version and
                        compare
  --print_json          Print the relevant output as JSON to stdout
  --get_ids             Retrieve GUID for the application_name and
                        version_name supplied
  --app_stats           Retrieve the latest risk and vulnerabiltiy for the
                        whole application
  --fail_if_issue_risk_over FAIL_IF_ISSUE_RISK_OVER
                        Causes the CLI to return a failure if any new issue
                        risk is over the integer specified
  --fail_if_risk_over FAIL_IF_RISK_OVER
                        Causes the CLI to return a failure if the risk is over
                        the integer specified
  --fail_if_risk_change_over FAIL_IF_RISK_CHANGE_OVER
                        Causes the CLI to return a failure if the percentage
                        change of increased risk is over the integer
                        specified. Requires 'test_and_compare' or
                        'compare_latest_results' functions
  --fail_if_issues_over FAIL_IF_ISSUES_OVER
                        Causes the CLI to return a failure if the number of
                        issues is over the integer specified
  --fail_if_issues_change_over FAIL_IF_ISSUES_CHANGE_OVER
                        Causes the CLI to return a failure if the percentage
                        change in new issues is over the integer specified.
                        Requires 'test_and_compare' or
                        'compare_latest_results' function
  --fail_if_CVSS_over FAIL_IF_CVSS_OVER
                        Causes the CLI to return a failure if the any new
                        issue has a CVSS over the integer specified. Requires
                        'test_and_compare' or 'compare_latest_results'
                        function
  --toolkit_name        The name of the toolkit you would like to use as part of your scan                      
  --debug               Prints debug messages

 ```


## Example usage:

```
# python3 uleska-automate.py --uleska_host https://uleska.example.com/ --application_name demo_UnSAFE_Bank --version_name v1 --token c64Ca28whEAIkFYlzO8clRutrlwVws2pF9999999999 --test_and_compare

Application or version name passed, looking up ids...
Application ID found for [demo_UnSAFE_Bank]: 00b17c86-62f8-4031-8fe9-d7ab319a0c3e
Version ID found for [v1]: a2bb3d88-cf9d-496f-9920-bee9122b43a0
Mapped names to ids: application name [demo_UnSAFE_Bank], id [00b17c86-62f8-4031-8fe9-d7ab319a0c3e], version name [v1] id [a2bb3d88-cf9d-496f-9920-bee9122b43a0]
Running blocking scan
Kicking off the scan
Scan running
Our Toolkit a2bb3d88-cf9d-496f-9920-bee9122b43a0 is still running, waiting...

Our Toolkit a2bb3d88-cf9d-496f-9920-bee9122b43a0 is still running, waiting...

Our Toolkit a2bb3d88-cf9d-496f-9920-bee9122b43a0 is still running, waiting...

No more scans running

Getting list of reports for this pipeline
Getting information on this report
Getting information on this report
Comparing the latest scan report with the previous one

=== Listing issues in Latest report =======================

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2017-2155] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2017-2155]
Cost [$62,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2018-6261] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2018-6261]
Cost [$62,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2018-1151] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2018-1151]
Cost [$62,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2016-9013] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2016-9013]
Cost [$62,000]

Issue [SQL_Injection: specificinputs.py] from tool [Demo Checkmarx]
Resource affected [/src/project/specificinputs.py]
Summary [Potential SQL injection found to be investigated.]
Cost [$44,000]

Issue [SQL_Injection: commoninputs.py] from tool [Demo Checkmarx]
Resource affected [/src/project/commoninputs.py]
Summary [Potential SQL injection found to be investigated.]
Cost [$81,000]

Issue [Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks: reinvent.py] from tool [Demo Bandit]
Resource affected [/]
Summary [Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called. Confidence Level: HIGH]
Cost [$10,000]

Issue [Possible hardcoded password: 'h++jszpm)i@p%ay_b=cp#()^od!qns14)h%@qm3)p=cuo+st^a'] from tool [Demo Bandit]
Resource affected [/]
Summary [Possible hardcoded password: 'h++jszpm)i@p%ay_b=cp#()^od!qns14)h%@qm3)p=cuo+st^a' Confidence Level: MEDIUM]
Cost [$62,000]

Issue [Possible hardcoded password: 'secret'] from tool [Demo Bandit]
Resource affected [/]
Summary [Possible hardcoded password: 'secret' Confidence Level: MEDIUM]
Cost [$62,000]

Issue [Database queries should not be vulnerable to injection attacks: create_view.py] from tool [Demo SonarQube]
Resource affected [/]
Summary [Database queries should not be vulnerable to injection attacks]
Cost [$312,000]

Issue [HTTP response headers should not be vulnerable to injection attacks] from tool [Demo SonarQube]
Resource affected [/]
Summary [HTTP response headers should not be vulnerable to injection attacks]
Cost [$81,000]

Issue [Databases should be password-protected.] from tool [Demo SonarQube]
Resource affected [/]
Summary [Databases should be password-protected]
Cost [$310,000]

Issue [Server certificates should be verified during SSL/TLS connections] from tool [Demo SonarQube]
Resource affected [/]
Summary [Server certificates should be verified during SSL/TLS connections]
Cost [$80,000]

Latest security toolkit run:
    Total risk:                   = $1,290,000
    Total issues:                 = 13

==============================================

=== Listing issues in Previous report =======================

Issue [Database queries should not be vulnerable to injection attacks: create_view.py] from tool [Demo SonarQube]
Resource affected [/]
Summary [Database queries should not be vulnerable to injection attacks]
Cost [$312,000]

Issue [Databases should be password-protected.] from tool [Demo SonarQube]
Resource affected [/]
Summary [Databases should be password-protected]
Cost [$310,000]

Issue [Server certificates should be verified during SSL/TLS connections] from tool [Demo SonarQube]
Resource affected [/]
Summary [Server certificates should be verified during SSL/TLS connections]
Cost [$80,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2017-2155] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2017-2155]
Cost [$62,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2018-6261] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2018-6261]
Cost [$62,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2018-1151] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2018-1151]
Cost [$62,000]

Issue [pkg:pypi/django@1.9.6 has the vulnerability CVE-2016-9013] from tool [Demo OWASP Dep Check]
Resource affected [/]
Summary [CVE-2016-9013]
Cost [$62,000]

Issue [SQL_Injection: specificinputs.py] from tool [Demo Checkmarx]
Resource affected [/src/project/specificinputs.py]
Summary [Potential SQL injection found to be investigated.]
Cost [$44,000]

Issue [SQL_Injection: commoninputs.py] from tool [Demo Checkmarx]
Resource affected [/src/project/commoninputs.py]
Summary [Potential SQL injection found to be investigated.]
Cost [$81,000]

Previous security toolkit run:
    Total risk:                   = $1,075,000
    Total issues:                 = 9

==============================================

    Risk level has INCREASED by    $215,000
    Risk level has INCREASED by     19.9%

    Number of issues has INCREASED by   4
    Number of issues has INCREASED by   44.4%

NEW ISSUE in this toolkit run:
        Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks: reinvent.py: tool [Demo Bandit]:     Risk $10,000
        CVSS : 6.2 : CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:N

NEW ISSUE in this toolkit run:
        Possible hardcoded password: 'h++jszpm)i@p%ay_b=cp#()^od!qns14)h%@qm3)p=cuo+st^a': tool [Demo Bandit]:     Risk $62,000
        CVSS : 7.3 : CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N

NEW ISSUE in this toolkit run:
        Possible hardcoded password: 'secret': tool [Demo Bandit]:     Risk $62,000
        CVSS : 7.3 : CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N

NEW ISSUE in this toolkit run:
        HTTP response headers should not be vulnerable to injection attacks: tool [Demo SonarQube]:     Risk $81,000
        CVSS : 8.2 : CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N

    New risk in this tookit run    = $215,000
```


## Detailed Info on the Paramaters


The Uleska CLI allows you to perform a number of functions as described below.  These functions will rely on a combination of parameters being passed.

### API Interaction

#### --uleska_host [hosturl]

REQUIRED.  This is the hostname (or hostname and domainname as needed) of the Uleska Platform the CLI script is to invoke the testing or commands on.  For example, if you have the Uleska Platform installed at uleska.example.com, you would set this parameter to https://uleska.example.com/ .  Note the scheme, and the final forward slash are required.

#### --token [token]

REQUIRED.  Provide the API authentication token retrieved for your chosen user.  See the relevant part of the Uleska documentation guide for more information on retrieving auth tokens from the Uleska Platform.

### Identifying the Application and Version to be tested

#### --application_name [name]

The text name of the application descriptor in the Uleska Platform to be tested.  This must be an exact string match (case sensitive).  Note - if application_name or version_name are supplied to the CLI then any application_id or version_id supplied will be ignored.  You must supply a combination of application_name and application_version to identify the testing toolkit and set up to be tested.

#### --version_name [name]

The text name of the version descriptor in the Uleska Platform to be tested.  This must be an exact string match (case sensitive).  Note - if application_name or version_name are supplied to the CLI then any applicaiton_id or version_id supplied will be ignored.  You must supply a combination of application_name and application_version to identify the testing toolkit and set up to be tested.

#### --applicaton_id [id]

The GUID associated with the application descriptor in the Uleska Platform.  This must be an exact string match.  The application ID can be retrieved using the 'get_ids' function of the CLI (see later), or can be viewed in the URL when accessing the application via the Uleska UI (after "/applications/").  Note - if application_name or version_name are supplied to the CLI then any applicaiton_id or version_id supplied will be ignored.

#### --version_id [id]

The GUID associated with the version descriptor in the Uleska Platform.  This must be an exact string match.  The version ID can be retrieved using the 'get_ids' function of the CLI (see later), or can be viewed in the URL when accessing the application via the Uleska UI (after "/versions/").  Note - if application_name or version_name are supplied to the CLI then any applicaiton_id or version_id supplied will be ignored.

#### --toolkit_name [name]

The name of the Toolkit you would like to use in your scan e.g. 'Uleska Code Scan'.  This must be an exact string match (case sensitive).

### Specifying the type of testing to be conducted

#### --test

Contacts the Uleska Platform API and invokes the testing toolkit for the application and version specified.  Requires a combination of application_name and version_name to be passed, or the application_id and version_id.  This starts the testing toolkit only, and returns immediately - i.e. runs in NON-BLOCKING mode.  If your pipeline wants to start the testing in one place, and then check the results later, this is the function to use.

#### --test_and_results

Contacts the Uleska Platform API and invokes the testing toolkit for the application and version specified, runs in BLOCKING mode, waiting for the testing toolkit to complete, when it then retrieves the results.  Requires a combination of application_name and version_name to be passed, or the application_id and version_id.  This will wait until the toolkit is finished, giving updates as it goes along.  When the toolkit has completed, it will retrieve the results of the latest report and display (as text or JSON, depending on the --print_json flag).  If your pipeline wants to start the testing and hold for the results of the latest tests to be shown, then use this function. Note that any results returned will not have 'invalid issues' displayed or compared (e.g. issues marked as false positives, duplicates, or non-issues).

#### --test_and_compare

Contacts the Uleska Platform API and invokes the testing toolkit for the application and version specified, as well as blocking for the testing toolkit to complete, when it then retrieves the latest results and compares those results to the previous results, highlighting any new or fixed issues.  Requires a combination of application_name and version_name to be passed, or the application_id and version_id.  Runs in BLOCKING mode until the toolkit is finished, giving updates as it goes along.  When the toolkit has completed, it will retrieve the results of the latest report, as well as the previous report, and display the differences in risk and issues between those reports (as text or JSON, depending on the --print_json flag).  If you want to know 'what's changed' since the last run through the pipeline, this function will highlight new issues found since the last run, as well as issues fixed.  It'll also show the differences in numbers of issues and risk.  This means you can program automated logic around the testing in your pipeline, e.g. flagging the build or alerting something if the risk or number of issues goes above a specified value, or if issues of type X are found, or based on CVSS, etc. Note that any results returned will not have 'invalid issues' displayed or compared (e.g. issues marked as false positives, duplicates, or non-issues).

#### --latest_results

Contacts the Uleska Platform API and only retrieves the results of the latest scan for the application and version specified. Requires a combination of application_name and version_name to be passed, or the application_id and version_id.  If your pipeline wants to start the testing somewhere else, and come back later for the results, this is the way to get those results in a NON-BLOCKING way.  This is the non-blocking equivalent of --test_and_results (only it doesn't kick off the tests). Note that any results returned will not have 'invalid issues' displayed or compared (e.g. issues marked as false positives, duplicates, or non-issues).

#### --compare_latest_results

Contacts the Uleska Platform API for the latest, and previous results related to the application and version specified, when it then compares those results to the previous results, highlighting any new or fixed issues.   Requires a combination of application_name and version_name to be passed, or the application_id and version_id.  If your pipeline wants to start the testing somewhere else, and come back later for the results to be compared to see what's changed since the last run, this is the way to get those results in a non-blocking way.  This is the non-blocking equivalent of --test_and_compare (only it doesn't kick off the tests). Note that any results returned will not have 'invalid issues' displayed or compared (e.g. issues marked as false positives, duplicates, or non-issues).

#### --app_stats

Contacts the Uleska Platform API to return high level risk and vulnerability data for the entire application, not just specific versions/stages.


### SAST Configuration updates

#### --update_sast

Flag to tell the CLI to expect configuration updates for SAST parameters, namely the Git Address, Git username, and/or Git auth token.  If this flag is set, at least --sast_git must be passed.  Note that the CLI SAST config updates can be used to update an existing SAST configuration for a version, it cannot be used to create a new version.

#### --sast_git [gitaddress]

Used in combination with --update_sast to update the Git Address configuration of the current application and version.  Value will be the full Git URL for the relevant codeline to be tested, e.g. "https://github.com/org/mycode.git".  This value will overwrite the existing Git Address configured for this version, equivalent to the 'Git Address' input in the UI.  Note setting this value automatically marks the 'Source Code Origin' flag to 'Git' for this version.

#### --sast_username [username]

Used in combination with --update_sast to update the Git Username configuration of the current application and version.  Value will be the username required to authenticate to the Git codeline to be tested. This value will overwrite the existing Git Username configured for this version, equivalent to the 'Username' input under 'SCM Authentication' in the UI.

#### --sast_token [token]

Used in combination with --update_sast to update the Git Password configuration of the current application and version.  Value will be the password or auth token required to authenticate to the Git codeline to be tested. This value will overwrite the existing Git Password configured for this version, equivalent to the 'Password' input under 'SCM Authentication' in the UI.

#### --tools [tools]

Used in combination with --update_sast to update the SAST toolkit of the current application and version.  Value will be a comma separated list of security tools configured for your testing.  This will overwite the existing toolkit configured.  For a list of tools configured for your environment, use the SecureDesigner/api/v1/tools API to list the tools and details (use the 'title' attribute as the tool name).  Example usage would be (--tools "Bandit,Dependency Checker,nodejs scan").


### Container Configuration updates

#### --update_container

Flag to tell the CLI to expect configuration updates for container parameters, namely the container image name, container image tag, and possibly the container connection name. If this flag is set, at least --container_image and --container_tag must be passed.  Note that the CLI container config updates can be used to update an existing container configuration for a version, it cannot be used to create a new version.

#### --container_image [name]

Used in combination with --update_container to update the Container Name configuration of the current application and version.  This value will overwrite the existing Container Name configured for this version, equivalent to the 'Container Name' input under 'Container' tab in the UI.

#### --container_tag [tag]

Used in combination with --update_container to update the Container Tag configuration of the current application and version.  This value will overwrite the existing Container Tag configured for this version, equivalent to the 'Tag' input under 'Container' tab in the UI.

#### --container_connection [connection]

Used in combination with --update_container to update the Container Connection configuration of the current application and version.  This value will overwrite the existing Container Connection configured for this version, equivalent to the 'Connection' input under 'Container' tab in the UI.


### Risk management

#### --fail_if_issue_risk_over [risk]

Usable with --test_and_results, --test_and_compare, --latest_results, --compare_latest_results.  Causes the CLI to return a failure (exit 1) if any individual issue in the results set returned has a risk value setting over the threshold set.  In the case of test commands that return the latest set of results (--test_and_results, --latest_results) this will cause a failure exit if any value in the latest result set is over the threshold.  In the case of test commands that compare the previous sets of results (--test_and_compare, --compare_latest_results) this will cause a failure exit if any value in the new issues found result set is over the threshold.


#### --fail_if_risk_over [risk]

Usable with --test_and_results, --test_and_compare, --latest_results, --compare_latest_results.  Causes the CLI to return a failure (exit 1) if the overall risk returned is over the threshold set.  In the case of test commands that return the latest set of results (--test_and_results, --latest_results) this will cause a failure exit if the risk of all issues in the latest result set is over the threshold.  In the case of test commands that compare the previous sets of results (--test_and_compare, --compare_latest_results) this will cause a failure exit if the combined risk of new issues found result set is over the threshold.


#### --fail_if_risk_change_over [percentage]

Usable with --test_and_compare, --compare_latest_results.  Causes the CLI to return a failure (exit 1) if the overall change in risk returned is over the percentage threshold set.  In the case of test commands that compare the previous sets of results (--test_and_compare, --compare_latest_results) this will cause a failure exit if the aggregate change in risk of new issues found result set is over the percentage threshold.


#### --fail_if_issues_over [number]

Usable with --test_and_results, --test_and_compare, --latest_results, --compare_latest_results.  Causes the CLI to return a failure (exit 1) if the overall number of issues returned is over the threshold set.  In the case of test commands that return the latest set of results (--test_and_results, --latest_results) this will cause a failure exit if the number of all issues in the latest result set is over the threshold.  In the case of test commands that compare the previous sets of results (--test_and_compare, --compare_latest_results) this will cause a failure exit if the number of new issues found result set is over the threshold.


#### --fail_if_issues_change_over [percentage]

Usable with --test_and_compare, --compare_latest_results.  Causes the CLI to return a failure (exit 1) if the overall change in numbers of issues returned is over the percentage threshold set.  In the case of test commands that compare the previous sets of results (--test_and_compare, --compare_latest_results) this will cause a failure exit if the aggregate change in numbers of new issues found result set is over the percentage threshold.


#### --fail_if_CVSS_over [CVSS number]

Usable with --test_and_results, --test_and_compare, --latest_results, --compare_latest_results.  Requires an integer number between 0 and 10.  Causes the CLI to return a failure (exit 1) if any individual issue in the results set returned has a CVSS value setting over the threshold set.  In the case of test commands that return the latest set of results (--test_and_results, --latest_results) this will cause a failure exit if any CVSS value in the latest result set is over the threshold.  In the case of test commands that compare the previous sets of results (--test_and_compare, --compare_latest_results) this will cause a failure exit if any CVSS value in the new issues found result set is over the threshold.


### Other functions

#### --print_json

Usable with --test_and_results, --test_and_compare, --latest_results, and --compare_latest_results.  Takes the information returned by the Uleska Platform and prints it to stdout in JSON format.

#### --get_ids

Helper function that takes in the --application_name and --version_name and gives the GUIDs associated with each.  Helpful when you don't have access to the UI, or are just to lazy to log in. 

#### --debug

Turns on debugging mode within the CLI script.  Nuf said.

For more details on the usage of the Uleska CLI, view the documentation at https://www.uleska.com


# Testing

To run tests, please run `python3 -m unittest`
