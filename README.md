# Introduction

## Development setup

```
git clone <repo>
cd threat-db
mkdir -p $HOME/dgraph $HOME/threatdb_data_dir
docker compose up
```

This would start a minimal api and an instance of [dgraph](https://dgraph.io) standalone.

## Create schemas

To explicitly create the schemas prior to importing data

```
git clone <repo>
poetry install
threat_db --init --dgraph-host localhost:9080 --graphql-host http://localhost:8080
```

Schema creation is automatic when the api runs from docker compose.

## Import data

```
threat_db --data-dir
```

When invoked with docker compose, any json file present in the directory `THREATDB_DATA_DIR` would be imported automatically.

## Rest API

### Healthcheck

```
curl http://0.0.0.0:9000/healthcheck
```

### Import data

```
curl -F 'file=@/tmp/bom.json' http://0.0.0.0:9000/import
```
