import click
import requests
import json
import yaml
from collections import OrderedDict


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


def operator_exists(rancher_url, system_project_id, headers, verify):
    operator_deployment_url = "%s/v3/project/%s/workloads/deployment:cattle-prometheus:prometheus-operator-monitoring-operator" % (rancher_url, system_project_id)
    operator_deployment_response = requests.get(operator_deployment_url, headers=headers, verify=verify)
    operator_deployment = json.loads(operator_deployment_response.content)
    return operator_deployment_response.status_code == 200

@click.command()
@click.option('--rancher-url', required=True, help="URL to source Rancher")
@click.option('--rancher-api-token', required=True, help="API Token for source Rancher")
@click.option('--cluster-id', required=True, help="ID for source cluster")
@click.option('--insecure', help="If set, do not verify tls certificates", is_flag=True)
def check_if_monitoring_is_disabled(rancher_url, rancher_api_token, cluster_id, insecure):
    verify=not insecure
    requests.packages.urllib3.disable_warnings()
    yaml.add_representer(OrderedDict, ordered_dict_presenter)

    headers = {
        "authorization": "Bearer %s" % rancher_api_token
    }
    
    # Get the cluster and check if its config enabled Monitoring or Alerting
    cluster_monitoring_enabled = False
    cluster_alerting_enabled = False
    cluster_url = "%s/v3/clusters/%s" % (rancher_url, cluster_id)
    cluster_response = requests.get(cluster_url, headers=headers, verify=verify)
    cluster = json.loads(cluster_response.content)
    if "enableClusterMonitoring" in cluster and cluster["enableClusterMonitoring"] == True:
        cluster_monitoring_enabled = True
    if "enableClusterAlerting" in cluster and cluster["enableClusterAlerting"] == True:
        cluster_alerting_enabled = True
    # Check if the Cluster Config is set from an RKE template
    if cluster_monitoring_enabled or cluster_alerting_enabled:
        if "clusterTemplateRevisionId" in cluster and cluster["clusterTemplateRevisionId"]:
            ctrid_url = "%s/v3/clustertemplaterevisions/%s" % (rancher_url, cluster["clusterTemplateRevisionId"])
            ctrid_response = requests.get(ctrid_url, headers=headers, verify=verify)
            ctrid = json.loads(ctrid_response.content)
            if "clusterConfig" in ctrid:
                cluster_config = ctrid["clusterConfig"]
                if cluster_config["enableClusterMonitoring"] or cluster_config["enableClusterAlerting"]:
                    print("The RKE template revision used to spin up the cluster enables Monitoring / Alerting V1. " + \
                          "You cannot switch to Monitoring V2 until you have updated your RKE template to set " + \
                          "enable_cluster_alerting=False and enable_cluster_monitoring=False.")
                    return

    # Get all projects
    project_monitoring_enabled = []
    projects_url = "%s/v3/projects" % (rancher_url)
    projects_response = requests.get(projects_url, headers=headers, verify=verify)
    projects_response.raise_for_status()
    projects = json.loads(projects_response.content)
    for project in projects["data"]:
        if project["clusterId"] != cluster_id:
            continue
        if "authz.management.cattle.io/system-project" in project["labels"]: 
            system_project_id = project["id"]
        elif "enableProjectMonitoring" in project and project["enableProjectMonitoring"] == True:
            project_monitoring_enabled.append({
                "name": project["name"],
                "id": project["id"]
            })

    if not operator_exists(rancher_url, system_project_id, headers, verify):
        print("The Monitoring V1 operator does not appear to exist in cluster %s. Migration to Monitoring V2 should be possible." % cluster_id)
        return
    
    print("Found Monitoring V1 operator in cluster %s. Auditing cluster to see why it is deployed...\n" % cluster_id)

    if not (cluster_monitoring_enabled or cluster_alerting_enabled or len(project_monitoring_enabled) > 0):
        print("Monitoring V1 should be disabled but the operator is still being deployed. Please file a bug with Rancher at https://github.com/rancher/rancher/issues/new.")

    print("Monitoring seems to be enabled because the following fields are set:")
    if cluster_monitoring_enabled:
        print("\tcluster.spec.enableClusterMonitoring=%s" % cluster_monitoring_enabled)
    if len(project_monitoring_enabled) > 0:
        print("\tproject.spec.enableProjectMonitoring=True for projects %s" % [p["name"] for p in project_monitoring_enabled])
    if cluster_alerting_enabled:
        print("\tcluster.spec.enableClusterAlerting=%s" % cluster_alerting_enabled)
    
    print("")
    
    if cluster_monitoring_enabled:
        print("To set cluster.spec.enableClusterMonitoring=False, click on Disable at %s/c/%s/monitoring/cluster-setting." % (rancher_url, cluster_id))
        print("")

    if len(project_monitoring_enabled) > 0:
        print("To set project.spec.enableProjectMonitoring=False, click on Disable at the following URLs:")
        for project in project_monitoring_enabled:
            print("Project %s: %s/p/%s/monitoring/project-setting" % (project["name"], rancher_url, project["id"]))
        print("")

    if cluster_alerting_enabled:
        # Check if Notifiers exist
        notifiers_url = "%s/v3/notifiers" % (rancher_url)
        notifiers_response = requests.get(notifiers_url, headers=headers, verify=verify)
        notifiers = json.loads(notifiers_response.content)
        if len(notifiers["data"]) == 0:
            print("cluster.spec.enableClusterAlerting should be set to False since no Notifiers exist. Please file a bug with Rancher at https://github.com/rancher/rancher/issues/new.")
            return
        # Check if any rules are asking for a Recipient
        groups_with_recipients = []
        cluster_alert_groups_url = "%s/v3/clusterAlertGroups" % (rancher_url)
        project_alert_groups_url = "%s/v3/projectAlertGroups" % (rancher_url)
        for group_url in [cluster_alert_groups_url, project_alert_groups_url]:
            alert_groups_response = requests.get(group_url, headers=headers, verify=verify)
            alert_groups = json.loads(alert_groups_response.content)
            for alert_group in alert_groups["data"]:
                group = {
                    "name": alert_group["name"],
                    "url": "%s/c/%s/alerts" % (rancher_url, cluster_id)
                }
                if "projectId" in alert_group:
                    if alert_group["projectId"].split(":")[0] != cluster_id:
                        continue
                    group["url"] = "%s/p/%s/alerts" % (rancher_url, alert_group["projectId"])
                else:
                    if alert_group["clusterId"] != cluster_id:
                        continue
                group["url"] += "/edit/%s" % (alert_group["id"])
                if "recipients" in alert_group and len(alert_group["recipients"]) > 0:
                    groups_with_recipients.append(group)

        print("To set cluster.spec.enableClusterAlerting=False, delete all notifiers in %s/c/%s/notifiers." % (rancher_url, cluster_id))
        print("Alternatively, you can remove recipients from all of the following Alert Groups (note: you will need to enable Monitoring to remove them):")
        print(yaml.dump(groups_with_recipients))

if __name__ == '__main__':
    check_if_monitoring_is_disabled()
