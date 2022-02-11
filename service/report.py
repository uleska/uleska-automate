import json
import sys

from model.failure_thresholds import FailureThresholds


def print_output_and_check_thresholds(report_issues, print_json: bool, thresholds: FailureThresholds) -> None:
    max_cvss_found: float = 0.0
    max_issue_risk_found: float = 0
    output = {}
    results_to_print = []
    overall_risk = 0

    for issue in report_issues:

        json_issue = {}
        json_issue['title'] = issue.title
        json_issue['tool'] = issue.tool
        json_issue['risk'] = issue.total_cost
        json_issue['cvss'] = issue.CVSS
        json_issue['summary'] = issue.summary
        json_issue['severity'] = issue.severity
        json_issue['explanation'] = issue.explanation
        json_issue['recommendation'] = issue.recommendation

        if issue.CVSS_value > max_cvss_found:
            max_cvss_found = issue.CVSS_value

        if issue.total_cost > max_issue_risk_found:
            max_issue_risk_found = issue.total_cost

        overall_risk += issue.total_cost

        results_to_print.append(json_issue)

    output['overall_risk'] = overall_risk
    output['num_issues'] = len(report_issues)
    output['issues'] = results_to_print

    if print_json:
        print(json.dumps(output, indent=4, sort_keys=True))

    check_thresholds(output, thresholds, max_issue_risk_found, max_cvss_found)


def check_thresholds(output, thresholds: FailureThresholds, max_issue_risk_found: float, max_cvss_found: float) -> None:
    if 0 < thresholds.fail_if_issue_risk_over < max_issue_risk_found:
        print("Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is " + str(
            max_issue_risk_found) + "].")
        sys.exit(1)

    if 0 < thresholds.fail_if_risk_over < output['overall_risk']:
        print("Returning failure as fail_if_risk_over threshold has been exceeded [risk is " + str(
            output['overall_risk']) + "].")
        sys.exit(1)

    if 0 < thresholds.fail_if_issues_over < output['num_issues']:
        print("Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is " + str(
            output['num_issues']) + "].")
        sys.exit(1)

    if 0 < thresholds.fail_if_CVSS_over < max_cvss_found:
        print("Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is " + str(
            max_cvss_found) + "].")
        sys.exit(1)
