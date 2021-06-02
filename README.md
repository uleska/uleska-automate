# uleska-automate
Uleska CLI for ease of integration with CI/CD and similar systems

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
