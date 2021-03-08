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

DefaultClusterDashboards = [
    "Cluster",
    "DaemonSet",
    "Deployment",
    "Etcd",
    "Kubernetes Components",
    "Kubernetes Resource Requests",
    "Nodes",
    "Pods",
    "Rancher Components",
    "StatefulSet"
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
@click.option('--insecure', help="If set, do not verify tls certificates", is_flag=True)
@click.option('--migrate-istio-dashboards', help="If set, Monitoring V1 Istio dashboards will automatically be migrated. This flag will be ignored if a project-id is provided.", is_flag=True)
@click.option('--migrate-default-dashboards', help="If set, Monitoring V1 default dashboards will automatically be migrated. This flag will be ignored if a project-id is provided.", is_flag=True)
def migrate(rancher_url, rancher_api_token, cluster_id, insecure, migrate_istio_dashboards, migrate_default_dashboards):
    verify=not insecure
    requests.packages.urllib3.disable_warnings()
    yaml.add_representer(OrderedDict, ordered_dict_presenter)

    headers = {
        "authorization": "Bearer %s" % rancher_api_token
    }

    projects_url = "%s/v3/projects" % rancher_url
    projects_response = requests.get(projects_url, headers=headers, verify=verify)
    projects = json.loads(projects_response.content)
    configmap_list = []

    for project in projects["data"]:
        project_id = project["id"].split(":")[1]
        base_url = "%s/k8s/clusters/%s/api/v1/namespaces/cattle-prometheus-%s/services/http:access-grafana:80/proxy" % (rancher_url, cluster_id, project_id)
        configmap_list = configmap_list + get_dashboards(base_url, headers, verify, migrate_istio_dashboards, migrate_default_dashboards, True)

    base_url = "%s/k8s/clusters/%s/api/v1/namespaces/cattle-prometheus/services/http:access-grafana:80/proxy" % (rancher_url, cluster_id)
    configmap_list = configmap_list + get_dashboards(base_url, headers, verify, migrate_istio_dashboards, migrate_default_dashboards, False)

    print("---\n".join(configmap_list))


def get_dashboards(base_url, headers, verify, migrate_istio_dashboards, migrate_default_dashboards, is_project):
    all_dashboards_response = requests.get("%s/api/search" % base_url, headers=headers, verify=verify)
    if all_dashboards_response.status_code == 404:
        return []
    all_dashboards = json.loads(all_dashboards_response.content)
    configmap_list = []

    for dashboard_ref in all_dashboards:
        dashboard_response = requests.get("%s/api/dashboards/uid/%s" % (base_url, dashboard_ref["uid"]),
                                          headers=headers, verify=verify)
        dashboard = json.loads(dashboard_response.content)
        dashboard_spec = dashboard["dashboard"]
        # Ignore migrating default dashboards if either:
        # 1) the user is trying to migrate from a project (should be migrated on a cluster level)
        # 2) if the relevant flag is not provided
        if (is_project or not migrate_istio_dashboards) and dashboard_spec["title"] in DefaultIstioDashboards:
            continue
        if (is_project or not migrate_default_dashboards) and dashboard_spec["title"] in DefaultClusterDashboards:
            continue
        if "tags" not in dashboard_spec:
            dashboard_spec["tags"] = []
        dashboard_spec["tags"].append("migrated")
        dashboard_spec["title"] = "V1/%s" % (dashboard_spec["title"])
        dashboard_json = json.dumps(dashboard_spec).replace("RANCHER_MONITORING", "Prometheus")

        config_map = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "migrated-dashboard-%s" % (dashboard["meta"]["slug"]),
                "namespace": "cattle-dashboards",
                "labels": {
                    "grafana_dashboard": "1"
                }
            },
            "data": OrderedDict(**{
                "v1-%s.json" % (dashboard["meta"]["slug"]): literal(dashboard_json)
            })
        }
        configmap_list.append(yaml.dump(config_map))

    return configmap_list


if __name__ == '__main__':
    migrate()
