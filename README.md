# rancher-monitoring v1 to v2 migration

Small helper scripts to migrate alerts and Grafana dashboards from monitoring v1 to v2 introduced in Rancher 2.5.

## Installation

The scripts are written in Python. The easiest option is to run them in a venv:

```
git clone https://github.com/bashofmann/rancher-monitoring-v1-to-v2.git
cd rancher-monitoring-v1-to-v2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Migrate Grafana dashboards

All dashboards will be exported. The script creates ConfigMaps that you can create in a cluster with monitoring v2 activated.

```
Usage: migrate_dashboards.py [OPTIONS]

Options:
  --rancher-url TEXT        URL to source Rancher  [required]
  --rancher-api-token TEXT  API Token for source Rancher  [required]
  --cluster-id TEXT         ID for source cluster  [required]
  --insecure                If set, do not verify tls certificates
  --help                    Show this message and exit.
```

Example:

```
python migrate_dashboards.py \
  --rancher-url https://rancher.example.com \
  --rancher-api-token ABCDEF
  --cluster-id c-123456 > dashboards.yaml

kubectl create -f dashboards.yaml
```

## Migrate Alerts

All metric based alerts will be exported. The script creates PrometheusRule objects that you can create in a cluster with monitoring v2 activated.

```
Usage: migrate_rules.py [OPTIONS]

Options:
  --rancher-url TEXT        URL to source Rancher  [required]
  --rancher-api-token TEXT  API Token for source Rancher  [required]
  --cluster-id TEXT         ID for source cluster  [required]
  --insecure                If set, do not verify tls certificates
  --help                    Show this message and exit.
```

Example:

```
python migrate_rules.py \
  --rancher-url https://rancher.example.com \
  --rancher-api-token ABCDEF
  --cluster-id c-123456 > rules.yaml

kubectl create -f rules.yaml
```

## Check why Monitoring V1 is not disabled

The script checks to see why the Monitoring V1 Operator might still be deployed on your cluster and outputs a report.

```
Usage: check_monitoring_disabled.py [OPTIONS]

Options:
  --rancher-url TEXT        URL to source Rancher  [required]
  --rancher-api-token TEXT  API Token for source Rancher  [required]
  --cluster-id TEXT         ID for source cluster  [required]
  --insecure                If set, do not verify tls certificates
  --help                    Show this message and exit.
```

Example:

```
python check_monitoring_disabled.py \
  --rancher-url https://rancher.example.com \
  --rancher-api-token ABCDEF
  --cluster-id c-123456
```

# Building and running with Docker

You can also run the scripts inside of a Docker image

## Building

```
make build -e VERSION=0.0.1
```

## Running

Example:

```
docker run bashofmann/rancher-monitoring-v1-to-v2:0.0.1 check_monitoring_disabled.py --rancher-url https://rancher.example.com --rancher-api-token $API_TOKEN --cluster-id $CLUSTER_ID
```