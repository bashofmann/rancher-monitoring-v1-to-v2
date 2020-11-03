import click
import requests
import json
import yaml
from collections import OrderedDict

DefaultIstioDashboards = [
    "istio",
    "Istio Citadel Dashboard",
    "Istio Galley Dashboard",
    "Istio Mesh Dashboard",
    "Istio Mixer Dashboard",
    "Istio Performance Dashboard",
    "Istio Pilot Dashboard",
    "Istio Service Dashboard",
    "Istio Workload Dashboard",
]

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
@click.option('--migrate-istio-dashboards', help="If set, Monitoring V1 Istio dashboards will automatically be migrated", is_flag=True)
def migrate(rancher_url, rancher_api_token, cluster_id, project_id, insecure, migrate_istio_dashboards):
    verify=not insecure
    requests.packages.urllib3.disable_warnings()
    yaml.add_representer(OrderedDict, ordered_dict_presenter)

    headers = {
        "authorization": "Bearer %s" % rancher_api_token
    }

    if project_id:
        base_url = "%s/k8s/clusters/%s/api/v1/namespaces/cattle-prometheus-%s/services/http:access-grafana:80/proxy" % (rancher_url, cluster_id, project_id)
        base_name = "-%s" % project_id
    else:
        base_url = "%s/k8s/clusters/%s/api/v1/namespaces/cattle-prometheus/services/http:access-grafana:80/proxy" % (rancher_url, cluster_id)
        base_name = ""

    all_dashboards_response = requests.get("%s/api/search" % base_url, headers=headers, verify=verify)

    all_dashboards = json.loads(all_dashboards_response.content)

    configmap_list = []

    for dashboard_ref in all_dashboards:
        dashboard_response = requests.get("%s/api/dashboards/uid/%s" % (base_url, dashboard_ref["uid"]),
                                          headers=headers, verify=verify)
        dashboard = json.loads(dashboard_response.content)
        dashboard_spec = dashboard["dashboard"]
        if not migrate_istio_dashboards and dashboard_spec["title"] in DefaultIstioDashboards:
            continue
        if "tags" not in dashboard_spec:
            dashboard_spec["tags"] = []
        dashboard_spec["tags"].append("migrated")
        dashboard_spec["title"] = "V1%s/%s" % (base_name, dashboard_spec["title"])
        dashboard_json = json.dumps(dashboard_spec).replace("RANCHER_MONITORING", "Prometheus")

        config_map = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "migrated-dashboard%s-%s" % (base_name, dashboard["meta"]["slug"]),
                "namespace": "cattle-dashboards",
                "labels": {
                    "grafana_dashboard": "1"
                }
            },
            "data": OrderedDict(**{
                "v1%s-%s.json" % (base_name, dashboard["meta"]["slug"]): literal(dashboard_json)
            })
        }
        configmap_list.append(yaml.dump(config_map))

    print("---\n".join(configmap_list))


if __name__ == '__main__':
    migrate()
