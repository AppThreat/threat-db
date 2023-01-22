# Introduction

This document contains the commands and configuration to setup an instance of threatdb API server with an HA dgraph backend on a microk8s for development and testing purposes. Neither microk8s nor the security settings used in this document are suitable for production servers!

## Microk8s Installation

```
sudo snap install microk8s --classic --channel=1.26/stable
microk8s status --wait-ready

microk8s enable cert-manager dns host-access hostpath-storage ingress rbac metrics-server
```

Sample output

```
$ microk8s status
microk8s is running
high-availability: no
  datastore master nodes: 127.0.0.1:19001
  datastore standby nodes: none
addons:
  enabled:
    cert-manager         # (core) Cloud native certificate management
    dns                  # (core) CoreDNS
    ha-cluster           # (core) Configure high availability on the current node
    helm                 # (core) Helm - the package manager for Kubernetes
    helm3                # (core) Helm 3 - the package manager for Kubernetes
    host-access          # (core) Allow Pods connecting to Host services smoothly
    hostpath-storage     # (core) Storage class; allocates storage from host directory
    ingress              # (core) Ingress controller for external access
    metrics-server       # (core) K8s Metrics Server for API access to service metrics
    rbac                 # (core) Role-Based Access Control for authorisation
    storage              # (core) Alias to hostpath-storage add-on, deprecated
  disabled:
    community            # (core) The community addons repository
    dashboard            # (core) The Kubernetes dashboard
    gpu                  # (core) Automatic enablement of Nvidia CUDA
    kube-ovn             # (core) An advanced network fabric for Kubernetes
    mayastor             # (core) OpenEBS MayaStor
    metallb              # (core) Loadbalancer for your Kubernetes cluster
    minio                # (core) MinIO object storage
    observability        # (core) A lightweight observability stack for logs, traces and metrics
    prometheus           # (core) Prometheus operator for monitoring and logging
    registry             # (core) Private image registry exposed on localhost:32000
```

## Kubernetes resources

Cluster issuer for creating ssl certificates via letsencrypt

```
microk8s kubectl apply -f - <<EOF
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    email: valid email here
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      # Secret resource that will be used to store the account's private key.
      name: letsencrypt-account-key
    # Add a single challenge solver, HTTP01 using nginx
    solvers:
    - http01:
        ingress:
          class: public
EOF
```

A storageclass for storing dgraph data in your local hard disk. Customize the `pvDir` based on your environment.

```
microk8s kubectl apply -f - <<EOF
---
# ssd-hostpath-sc.yaml
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: ssd-hostpath
provisioner: microk8s.io/hostpath
reclaimPolicy: Delete
parameters:
  pvDir: /data/k8s
volumeBindingMode: WaitForFirstConsumer
EOF
```

## Installing dgraph server via helm

Create an helm values file called `dgraph-values.yaml` with your dgraph [configuration](https://github.com/dgraph-io/charts/blob/master/charts/dgraph/values.yaml). Use the below configuration as an example and customize the security token, domain names and whitelist IPs based on your needs.

```
# dgraph-values.yaml
image:
  tag: "v22.0.1"
zero:
  resources:
    requests:
      cpu: 500m
      memory: "1Gi"
    limits:
      cpu: 1
      memory: "2Gi"
  persistence:
    storageClass: "ssd-hostpath"
    size: 25Gi
  extraFlags: "--telemetry 'reports=false;sentry=false;' --limit 'disable-admin-http=true;'"
alpha:
  resources:
    requests:
      cpu: 1
      memory: "4Gi"
    limits:
      cpu: 2
      memory: "16Gi"
  persistence:
    storageClass: "ssd-hostpath"
    size: 50Gi
  extraFlags: "--telemetry 'reports=false;sentry=false;' --badger 'compression=zstd:1' --security 'token=changeme;whitelist=10.1.0.0/16,127.0.0.1' --graphql 'introspection=false;debug=false;'"

global:
  ingress:
    enabled: false
    ingressClassName: public
    annotations:
      kubernetes.io/ingress.class: nginx
      cert-manager.io/cluster-issuer: letsencrypt
      kubernetes.io/ingress.class: "public"
    ratel_hostname: "ratel.domain.com"
    alpha_hostname: "gql.domain.com"
  ingress_grpc:
    enabled: false
    ingressClassName: public
    alpha_grpc_hostname: rpc1.domain.com
    annotations:
      kubernetes.io/ingress.class: nginx
      cert-manager.io/cluster-issuer: letsencrypt
      kubernetes.io/ingress.class: "public"
```

Use helm to create an HA installation.

```
microk8s helm repo add dgraph https://charts.dgraph.io
microk8s helm install dev-db dgraph/dgraph --values dgraph-values.yaml
# microk8s helm uninstall dev-db
microk8s kubectl get pods
```

Example output

```
$ microk8s kubectl get pv
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                   STORAGECLASS   REASON   AGE
pvc-69e20d51-f972-4bd9-aac0-23c393a5dcb8   25Gi       RWO            Delete           Bound    default/datadir-dev-db-dgraph-zero-0    ssd-hostpath            30m
pvc-0678a1c7-6dff-437a-ad1f-b845bbfe7edf   50Gi       RWO            Delete           Bound    default/datadir-dev-db-dgraph-alpha-0   ssd-hostpath            30m
pvc-43f75edc-08d5-4dab-b44a-623cdd3cd381   25Gi       RWO            Delete           Bound    default/datadir-dev-db-dgraph-zero-1    ssd-hostpath            30m
pvc-07755bd7-3886-45d3-9d0e-66783a7c6ef5   50Gi       RWO            Delete           Bound    default/datadir-dev-db-dgraph-alpha-1   ssd-hostpath            30m
pvc-46c68e46-598f-4d2a-99d1-03b3cfdcd4cc   25Gi       RWO            Delete           Bound    default/datadir-dev-db-dgraph-zero-2    ssd-hostpath            29m
pvc-a1eb4ac7-a52e-4ab7-8c90-79166099c856   50Gi       RWO            Delete           Bound    default/datadir-dev-db-dgraph-alpha-2   ssd-hostpath            29m
```

```
$ microk8s kubectl get pvc
NAME                            STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
datadir-dev-db-dgraph-zero-0    Bound    pvc-69e20d51-f972-4bd9-aac0-23c393a5dcb8   25Gi       RWO            ssd-hostpath   30m
datadir-dev-db-dgraph-alpha-0   Bound    pvc-0678a1c7-6dff-437a-ad1f-b845bbfe7edf   50Gi       RWO            ssd-hostpath   30m
datadir-dev-db-dgraph-zero-1    Bound    pvc-43f75edc-08d5-4dab-b44a-623cdd3cd381   25Gi       RWO            ssd-hostpath   30m
datadir-dev-db-dgraph-alpha-1   Bound    pvc-07755bd7-3886-45d3-9d0e-66783a7c6ef5   50Gi       RWO            ssd-hostpath   30m
datadir-dev-db-dgraph-zero-2    Bound    pvc-46c68e46-598f-4d2a-99d1-03b3cfdcd4cc   25Gi       RWO            ssd-hostpath   30m
datadir-dev-db-dgraph-alpha-2   Bound    pvc-a1eb4ac7-a52e-4ab7-8c90-79166099c856   50Gi       RWO            ssd-hostpath   30m
```

```
$ microk8s kubectl get pods
NAME                    READY   STATUS    RESTARTS   AGE
dev-db-dgraph-alpha-0   1/1     Running   0          29m
dev-db-dgraph-zero-0    1/1     Running   0          29m
dev-db-dgraph-zero-1    1/1     Running   0          29m
dev-db-dgraph-alpha-1   1/1     Running   0          29m
dev-db-dgraph-zero-2    1/1     Running   0          29m
dev-db-dgraph-alpha-2   1/1     Running   0          29m
```

```
$ microk8s kubectl get service
NAME                           TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)             AGE
kubernetes                     ClusterIP   10.152.183.1     <none>        443/TCP             52m
dev-db-dgraph-zero-headless    ClusterIP   None             <none>        5080/TCP            29m
dev-db-dgraph-alpha-headless   ClusterIP   None             <none>        7080/TCP            29m
dev-db-dgraph-alpha            ClusterIP   10.152.183.110   <none>        8080/TCP,9080/TCP   29m
dev-db-dgraph-zero             ClusterIP   10.152.183.112   <none>        5080/TCP,6080/TCP   29m
```

## Install threatdb API server

```
# microk8s helm uninstall threat-db-api
microk8s helm install threat-db-api oci://ghcr.io/appthreat/charts/threat-db --version 0.6.2 --set persistence.storageClass="ssd-hostpath" --set persistence.size="1Gi"
microk8s kubectl get pods

microk8s kubectl logs --tail=10 threat-db-api-0
```

## Create Kubernetes Ingress

Copy the contents below to a file called `ing.yaml`. Customize the host and service names based on your environment.

```
# ing.yaml
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-http-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt"
    kubernetes.io/ingress.class: "public"
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/modsecurity-transaction-id: "$request_id"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-body-size: 10m
    nginx.ingress.kubernetes.io/proxy-max-temp-file-size: "1024m"
    nginx.ingress.kubernetes.io/proxy-buffering: "on"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
    nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers: "true"
spec:
  tls:
    - hosts:
      - api.domain.com
      secretName: api-alpha-tls
  rules:
  - host: "api.domain.com"
    http:
      paths:
      - path: /login
        pathType: Prefix
        backend:
          service:
            name: threat-db-api
            port:
              number: 8000
      - path: /import
        pathType: Prefix
        backend:
          service:
            name: threat-db-api
            port:
              number: 8000
      - path: /healthcheck
        pathType: Prefix
        backend:
          service:
            name: threat-db-api
            port:
              number: 8000
      - path: /graphql
        pathType: Prefix
        backend:
          service:
            name: threat-db-api
            port:
              number: 8000
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: gql-http-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt"
    kubernetes.io/ingress.class: "public"
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/modsecurity-transaction-id: "$request_id"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/whitelist-source-range: 10.152.0.0/16,10.1.0.0/16,127.0.0.1
    nginx.ingress.kubernetes.io/proxy-body-size: 10m
    nginx.ingress.kubernetes.io/proxy-max-temp-file-size: "1024m"
    nginx.ingress.kubernetes.io/proxy-buffering: "on"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
    nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers: "true"
spec:
  tls:
    - hosts:
      - gql.domain.com
      secretName: gql-alpha-tls
  rules:
  - host: "gql.domain.com"
    http:
      paths:
      - path: /graphql
        pathType: Prefix
        backend:
          service:
            name: dev-db-dgraph-alpha
            port:
              number: 8080
      - path: /admin
        pathType: Prefix
        backend:
          service:
            name: dev-db-dgraph-alpha
            port:
              number: 8080
      - path: /alter
        pathType: Prefix
        backend:
          service:
            name: dev-db-dgraph-alpha
            port:
              number: 8080
      - path: /login
        pathType: Prefix
        backend:
          service:
            name: dev-db-dgraph-alpha
            port:
              number: 8080
      - path: /health
        pathType: Prefix
        backend:
          service:
            name: dev-db-dgraph-alpha
            port:
              number: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rpc1-http-ingress
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt"
    kubernetes.io/ingress.class: "public"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
    nginx.ingress.kubernetes.io/whitelist-source-range: 10.152.0.0/16,10.1.0.0/16,127.0.0.1
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
    nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers: "true"
spec:
  tls:
    - hosts:
      - rpc1.domain.com
      secretName: rpc-alpha-tls
  rules:
  - host: "rpc1.domain.com"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: dev-db-dgraph-alpha
            port:
              number: 9080
```

Apply the ingress

```
microk8s kubectl apply -f ing.yaml
```

Sample output

```
$ microk8s kubectl get ingress
NAME               CLASS    HOSTS                      ADDRESS     PORTS     AGE
gql-http-ingress   <none>   gql.domain.com,rpc1.domain.com   127.0.0.1   80, 443   4m58s
```

Extra ingress annotations

```
nginx.ingress.kubernetes.io/limit-connections: 10
nginx.ingress.kubernetes.io/limit-rps: 10
nginx.ingress.kubernetes.io/limit-whitelist: 127.0.0.1
```

## Troubleshooting

Check pod logs

```
microk8s kubectl logs dev-db-dgraph-alpha-2
```

Check pod limits

```
microk8s kubectl get pods dev-db-dgraph-zero-0 -o jsonpath='{range .spec.containers[*]}{"Container Name: "}{.name}{"\n"}{"Requests:"}{.resources.requests}{"\n"}{"Limits:"}{.resources.limits}{"\n"}{end}'
```


