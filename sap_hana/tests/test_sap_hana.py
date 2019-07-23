# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from datadog_checks.sap_hana import SapHanaCheck


def test_check(aggregator, instance):
    check = SapHanaCheck('sap_hana', {}, [{}])
    check.check(instance)

    aggregator.assert_all_metrics_covered()
