import click
import requests
import json
import yaml
from collections import OrderedDict

ComparisonHasValue = "has-value"
ComparisonEqual = "equal"
ComparisonNotEqual = "not-equal"
ComparisonGreaterThan = "greater-than"
ComparisonLessThan = "less-than"
ComparisonGreaterOrEqual = "greater-or-equal"
ComparisonLessOrEqual = "less-or-equal"

comparisonMap = {
    ComparisonHasValue: "",
    ComparisonEqual: "==",
    ComparisonNotEqual: "!=",
    ComparisonGreaterThan: ">",
    ComparisonLessThan: "<",
    ComparisonGreaterOrEqual: ">=",
    ComparisonLessOrEqual: "<=",
}


class quoted(str):
    pass


def quoted_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')


yaml.add_representer(quoted, quoted_presenter)


class literal(str):
    pass


def literal_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')


yaml.add_representer(literal, literal_presenter)


def ordered_dict_presenter(dumper, data):
    return dumper.represent_dict(data.items())


@click.command()
@click.option('--rancher-url', required=True, help="URL to source Rancher")
@click.option('--rancher-api-token', required=True, help="API Token for source Rancher")
@click.option('--cluster-id', required=True, help="ID for source cluster")
@click.option('--project-id', help="ID for source project (optional)")
@click.option('--insecure', help="If set, do not verify tls certificates", is_flag=True)
def migrate(rancher_url, rancher_api_token, cluster_id, project_id, insecure):
    verify=not insecure
    requests.packages.urllib3.disable_warnings()
    yaml.add_representer(OrderedDict, ordered_dict_presenter)

    headers = {
        "authorization": "Bearer %s" % rancher_api_token
    }

    if project_id:
        url = "%s/v3/projects/%s:%s/projectalertrules" % (rancher_url, cluster_id, project_id)
        name = "monitoring-v1-rules-%s-%s" % (cluster_id, project_id)
    else:
        url = "%s/v3/clusterAlertRules?clusterId=%s" % (rancher_url, cluster_id)
        name = "monitoring-v1-rules-%s" % cluster_id

    cluster_alert_rules_response = requests.get(url, headers=headers, verify=verify)

    cluster_alert_rules = json.loads(cluster_alert_rules_response.content)

    rules = []

    for cluster_alert_rule in cluster_alert_rules["data"]:
        if cluster_alert_rule["creatorId"] and cluster_alert_rule["metricRule"]:
            metric_rule = cluster_alert_rule["metricRule"]
            prometheus_expression = get_prometheus_expression(
                metric_rule["expression"],
                metric_rule["comparison"],
                metric_rule["thresholdValue"]
            )
            rule = OrderedDict(**{
                "alert": literal(cluster_alert_rule["name"]),
                "expr": literal(prometheus_expression),
                "for": cluster_alert_rule["metricRule"]["duration"],
                "labels": {
                    "severity": cluster_alert_rule["severity"]
                },
                "annotations": OrderedDict(
                    message=literal("Query %s is %s %s. Current value {{ $value }}" % (
                        metric_rule["expression"],
                        metric_rule["comparison"],
                        metric_rule["thresholdValue"]
                    ))
                )
            })
            rules.append(rule)

    prometheus_rules = {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": name,
            "namespace": "cattle-monitoring-system"
        },
        "spec": {
            "groups": [
                {
                    "name": name,
                    "rules": rules
                }
            ]
        }
    }

    print(yaml.dump(prometheus_rules))


def get_prometheus_expression(expression, comparison, threshold_value):
    if comparison != ComparisonHasValue:
        return "%s%s%s" % (expression, comparisonMap[comparison], threshold_value)
    return expression


if __name__ == '__main__':
    migrate()
