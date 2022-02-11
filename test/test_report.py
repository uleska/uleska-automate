from unittest import TestCase

from model.failure_thresholds import FailureThresholds
from service.report import check_thresholds


class ReportTest(TestCase):

    def test_check_threshold_does_not_exit_if_no_threshold_values_set(self):
        # given
        output = {
            'overall_risk': 0,
            'num_issues': 0,
            'issues': []
        }
        thresholds = FailureThresholds()

        # when - then
        check_thresholds(output, thresholds, 0, 0)

    def test_check_threshold_does_not_exit_if_risk_over_is_below_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_risk_over = 2

        # when - then
        check_thresholds(output, thresholds, 0, 0)

    def test_check_threshold_exits_if_risk_over_is_above_thresholds(self):
        # given
        output = {
            'overall_risk': 2,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_risk_over = 1

        # when
        with self.assertRaises(SystemExit) as cm:
            check_thresholds(output, thresholds, 0, 0)

        # then
        self.assertEqual(cm.exception.code, 1)

    def test_check_threshold_does_not_exit_if_issue_risk_over_is_below_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_issue_risk_over = 2

        # when - then
        check_thresholds(output, thresholds, 1, 0)

    def test_check_threshold_exits_if_issue_risk_over_is_above_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_issue_risk_over = 1

        # when
        with self.assertRaises(SystemExit) as cm:
            check_thresholds(output, thresholds, 2, 0)

        # then
        self.assertEqual(cm.exception.code, 1)

    def test_check_threshold_does_not_exit_if_issues_over_is_below_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_issues_over = 2

        # when - then
        check_thresholds(output, thresholds, 0, 0)

    def test_check_threshold_exits_if_issues_over_is_above_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 2,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_issues_over = 1

        # when
        with self.assertRaises(SystemExit) as cm:
            check_thresholds(output, thresholds, 0, 0)

        # then
        self.assertEqual(cm.exception.code, 1)

    def test_check_threshold_does_not_exit_if_max_cvss_over_is_below_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_CVSS_over = 2

        # when - then
        check_thresholds(output, thresholds, 0, 1)

    def test_check_threshold_exits_if_max_cvss_over_is_above_thresholds(self):
        # given
        output = {
            'overall_risk': 1,
            'num_issues': 1,
            'issues': []
        }
        thresholds = FailureThresholds()
        thresholds.fail_if_CVSS_over = 1

        # when
        with self.assertRaises(SystemExit) as cm:
            check_thresholds(output, thresholds, 0, 2)

        # then
        self.assertEqual(cm.exception.code, 1)