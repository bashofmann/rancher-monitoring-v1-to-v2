import click
import requests
import json
import yaml
import base64
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
@click.option('--insecure', help="If set, do not verify tls certificates", is_flag=True)
def migrate(rancher_url, rancher_api_token, cluster_id, insecure):
    verify=not insecure
    requests.packages.urllib3.disable_warnings()
    yaml.add_representer(OrderedDict, ordered_dict_presenter)

    headers = {
        "authorization": "Bearer %s" % rancher_api_token
    }

    # Get System Project
    projects_url = "%s/v3/projects" % (rancher_url)
    projects_response = requests.get(projects_url, headers=headers, verify=verify)
    projects = json.loads(projects_response.content)
    for project in projects["data"]:
        if project["clusterId"] != cluster_id:
            continue
        if "authz.management.cattle.io/system-project" in project["labels"]: 
            system_project_id = project["id"]
            break

    # Get Alertmanager Config
    alerting_config_url = "%s/v3/project/%s/namespacedSecrets/cattle-prometheus:alertmanager-cluster-alerting" % (rancher_url, system_project_id)
    alerting_config_response = requests.get(alerting_config_url, headers=headers, verify=verify)
    alerting_config = json.loads(alerting_config_response.content)
    alertmanager_yaml = yaml.safe_load(
        base64_decode(alerting_config["data"]["alertmanager.yaml"])
    )

    # Get Notifiers by ID
    notifiers_by_id = {}
    notifiers_url = "%s/v3/notifier" % (rancher_url)
    notifiers_response = requests.get(notifiers_url, headers=headers, verify=verify)
    notifiers = json.loads(notifiers_response.content)
    for notifier in notifiers["data"]:
        if notifier["clusterId"] != cluster_id:
            continue
        notifier_id = notifier["id"]
        notifiers_by_id[notifier_id] = {
            "name": notifier["name"],
            "group_ids": []
        }

    # Gather PrometheusRules from AlertGroups / AlertRules
    prometheus_rules = []
    cluster_alert_groups_url = "%s/v3/clusterAlertGroups" % (rancher_url)
    project_alert_groups_url = "%s/v3/projectAlertGroups" % (rancher_url)
    for group_url in [cluster_alert_groups_url, project_alert_groups_url]:
        alert_groups_response = requests.get(group_url, headers=headers, verify=verify)
        alert_groups = json.loads(alert_groups_response.content)
        for alert_group in alert_groups["data"]:
            if "projectId" in alert_group:
                if alert_group["projectId"].split(":")[0] != cluster_id:
                    continue
                if alert_group["projectId"] == system_project_id:
                    continue
                alert_rules_response = requests.get(alert_group["links"]["projectAlertRules"], headers=headers, verify=verify)
            else:
                if alert_group["clusterId"] != cluster_id:
                    continue
                alert_rules_response = requests.get(alert_group["links"]["clusterAlertRules"], headers=headers, verify=verify)

            alert_rules = json.loads(alert_rules_response.content)

            rules = []
            for alert_rule in alert_rules["data"]:
                if not alert_rule["creatorId"] or not alert_rule["metricRule"]:
                    continue
                metric_rule = alert_rule["metricRule"]
                prometheus_expression = get_prometheus_expression(
                    metric_rule["expression"],
                    metric_rule["comparison"],
                    metric_rule["thresholdValue"]
                )
                message = get_message(
                    metric_rule["expression"],
                    metric_rule["comparison"],
                    metric_rule["thresholdValue"]
                )
                rule = OrderedDict(**{
                    "alert": literal(alert_rule["name"]),
                    "expr": literal(prometheus_expression),
                    "for": metric_rule["duration"],
                    "labels": {
                        "severity": alert_rule["severity"],
                        "group_id": alert_group["id"]
                    },
                    "annotations": OrderedDict(
                        message=literal(message),
                    )
                })
                rules.append(rule)

            if len(rules) == 0:
                continue

            group_id = alert_group["id"].split(":")[1]
            prometheus_rule = {
                "apiVersion": "monitoring.coreos.com/v1",
                "kind": "PrometheusRule",
                "metadata": {
                    "name": "rancher-alerting-v1-%s" % (group_id),
                    "namespace": "cattle-monitoring-system",
                    "labels": {
                        "source": "rancher-alerting-v1"
                    },
                    "annotations": {}
                },
                "spec": {
                    "groups": [
                        OrderedDict(**{
                            "name": alert_group["name"],
                            "interval": "%ss" % (alert_group["groupIntervalSeconds"]),
                            "rules": rules
                        })
                    ]
                }
            }
            if "description" in alert_group:
                prometheus_rule["metadata"]["annotations"]["field.cattle.io/description"] = alert_group["description"]

            prometheus_rules.append(prometheus_rule)

            if "recipients" in alert_group:
                for recipient in alert_group["recipients"]:
                    notifier_id = recipient["notifierId"]
                    notifiers_by_id[notifier_id]["group_ids"].append(alert_group["id"])

    alertmanager_yaml = update_alertmanager_config(alertmanager_yaml, notifiers_by_id)

    print(yaml.dump(alertmanager_yaml), end="---\n")

    # Create resources
    namespace = OrderedDict(**{
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": "cattle-monitoring-system"
        }
    })

    alerting_config = OrderedDict(**{
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "alertmanager-rancher-monitoring-alertmanager",
            "namespace": "cattle-monitoring-system",
            "labels": {
                "source": "rancher-alerting-v1"
            },
        },
        "data": {
            "alertmanager.yaml": literal(base64_encode(yaml.dump(alertmanager_yaml))),
            "notification.tmpl": literal(alerting_config["data"]["notification.tmpl"])
        },
        "type": "Opaque"
    })
    
    resources = [namespace, alerting_config]

    resources.extend(prometheus_rules)

    print(yaml.dump_all(resources))

def update_alertmanager_config(alertmanager_yaml, notifiers_by_id):
    alertmanager_yaml["route"]["receiver"] = "null"
    alertmanager_yaml["route"]["group_by"] = ['job']
    alertmanager_yaml["templates"] = ["/etc/alertmanager/config/*.tmpl"]
    
    # Update to one Receiever per Notifier instead of one per alert group
    receiver_by_group_id = {}
    receivers = [{"name": "null"}]
    for notifier_id in notifiers_by_id:
        notifier = notifiers_by_id[notifier_id]
        if len(notifier["group_ids"]) == 0:
            continue
        # Get receiver configuration
        first_matching_notifier = notifier["group_ids"][0]
        receiver = [r for r in alertmanager_yaml["receivers"] if r["name"] == first_matching_notifier][0]
        receiver["name"] = notifier["name"]
        receivers.append(receiver)
        # Keep track of what group_ids need to be modified
        for group_id in notifier["group_ids"]:
            receiver_by_group_id[group_id] = receiver["name"]
    alertmanager_yaml["receivers"] = receivers
    
    # Update Recievers attached to routes accordingly
    alertmanager_yaml["route"]["receiver"] = "null"
    alertmanager_yaml["route"]["group_by"] = ['job']
    routes = []
    for route in alertmanager_yaml["route"]["routes"]:
        # Rule-specific routes are not supported
        del route["routes"]
        group_id = route["receiver"]
        if group_id in receiver_by_group_id:
            route["receiver"] = receiver_by_group_id[group_id]
            routes.append(route)
    alertmanager_yaml["route"]["routes"] = routes
    
    return alertmanager_yaml


def get_prometheus_expression(expression, comparison, threshold_value):
    if comparison != ComparisonHasValue:
        return "%s%s%s" % (expression, comparisonMap[comparison], threshold_value)
    return expression


def get_message(expression, comparision, threshold_value):
    comparision = comparision.replace("-", " ")
    if "equal" in comparision:
        comparision += " to"
    return "Query %s is %s %s. Current value is {{ $value }}." % (expression, comparision, threshold_value)


def base64_decode(base64_msg):
    base64_msg_bytes = base64_msg.encode('ascii')
    msg_bytes = base64.b64decode(base64_msg_bytes)
    return msg_bytes.decode('ascii')


def base64_encode(msg):
    msg_bytes = msg.encode('ascii')
    base64_msg_bytes = base64.b64encode(msg_bytes)
    return base64_msg_bytes.decode('ascii')


if __name__ == '__main__':
    migrate()
