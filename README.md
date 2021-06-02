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
                          [--version_name VERSION_NAME] [--test]
                          [--test_and_results] [--test_and_compare]
                          [--latest_results] [--compare_latest_results]
                          [--get_ids] [--debug]

Uleska command line interface. To identify the project/pipeline to test you
can specify either --application_name and --version_name, or --application and
--version (passing GUIDs). (Version 0.2)

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
                        Retrieve the latest test results for application and
                        version and compare
  --get_ids             Retrieve GUID for the application_name and
                        version_name supplied
  --debug               Prints debug messages
 ```

Example usage:

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

For more details on the usage of the Uleska CLI, view the documentation at https://www.uleska.com
