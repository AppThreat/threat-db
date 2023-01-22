# Introduction

ThreatDB is a graph database for application components and vulnerabilities powered by dgraph. Currently, CycloneDX 1.4 SBoM and VEX files could be imported and queried with this project.

## Development setup

```
git clone https://github.com/appthreat/threat-db.git
cd threat-db
mkdir -p $HOME/dgraph $HOME/threatdb_data_dir
docker compose up
```

This would start a threat db api server (PORT: 9000) and an instance of [dgraph](https://dgraph.io) standalone (PORTS: 8080, 9080).

## Create schemas

To create the schemas and the first administrator user.

```
git clone https://github.com/appthreat/threat-db.git
pip install poetry
poetry install
export DGRAPH_API_KEY=changeme
poetry run threat_db_admin --init --dgraph-host localhost:9080 --graphql-host http://localhost:8080/graphql
poetry run threat_db_admin --create-root-user --dgraph-host localhost:9080 --graphql-host http://localhost:8080/graphql
```

Copy the user id and password from the logs.

## Import data

```
mkdir -p $HOME/threatdb_data_dir
threat_db --data-dir $HOME/threatdb_data_dir
```

When invoked with docker compose, any .vex.json files present in the directory `THREATDB_DATA_DIR` would be imported automatically. For testing purposes, you can download some sample VEX files from [here](https://github.com/appthreat/images-info/actions/workflows/build.yml)

## Rest API

### Generate access token

```
curl -X POST http://0.0.0.0:9000/login -d "username=user id&password=password" -H "Content-Type: application/json"
```

Useful one-liner for automation

```
export ACCESS_TOKEN=$(curl -X POST http://0.0.0.0:9000/login -d '{"username":"username","password":"password"}' -H "Content-Type: application/json" | jq -r '.access_token')
```

```
curl http://0.0.0.0:9000/healthcheck
```

### whoami

```
curl http://0.0.0.0:9000/whoami -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Import data

```
curl -F 'file=@/tmp/bom.json' http://0.0.0.0:9000/import -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Cloud Setup

Refer to the instructions under [contrib](contrib/microk8s/INSTALL.md) to setup a microk8s cluster with threat-db and dgraph.

## Discord support

The developers could be reached via the [discord](https://discord.gg/DCNxzaeUpd) channel.
