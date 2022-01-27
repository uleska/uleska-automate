import json
import sys

from model.failure_thresholds import FailureThresholds


def print_output_and_check_thresholds(results, print_json: bool, thresholds: FailureThresholds) -> None:
    max_cvss_found: float = 0.0
    max_issue_risk_found: float = 0
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

    check_thresholds(output, thresholds, max_issue_risk_found, max_cvss_found)


def check_thresholds(output, thresholds: FailureThresholds, max_issue_risk_found: float, max_cvss_found: float) -> None:
    if thresholds.fail_if_issue_risk_over > 0 and max_issue_risk_found > thresholds.fail_if_issue_risk_over:
        print("Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is " + str(
            max_issue_risk_found) + "].")
        sys.exit(1)

    if thresholds.fail_if_risk_over > 0 and output['overall_risk'] > thresholds.fail_if_risk_over:
        print("Returning failure as fail_if_risk_over threshold has been exceeded [risk is " + str(
            output['overall_risk']) + "].")
        sys.exit(1)

    if thresholds.fail_if_issues_over > 0 and output['num_issues'] > thresholds.fail_if_issues_over:
        print("Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is " + str(
            output['num_issues']) + "].")
        sys.exit(1)

    if thresholds.fail_if_CVSS_over > 0 and max_cvss_found > thresholds.fail_if_CVSS_over:
        print("Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is " + str(
            max_cvss_found) + "].")
        sys.exit(1)
