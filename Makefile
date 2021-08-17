VERSION=0.0.1
REGISTRY=bashofmann
IMAGE=rancher-monitoring-v1-to-v2

build:
	docker build . -t ${REGISTRY}/${IMAGE}:${VERSION}

push:
	docker push ${REGISTRY}/${IMAGE}:${VERSION}
