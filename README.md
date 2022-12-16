# Introduction

## Development setup

```
git clone https://github.com/ngcloudsec/threat-db.git
cd threat-db
mkdir -p $HOME/dgraph $HOME/threatdb_data_dir
docker compose up
```

This would start a threat db api server (PORT: 9000) and an instance of [dgraph](https://dgraph.io) standalone (PORTS: 8080, 9080).

## Create schemas

To create the schemas and the first administrator user.

```
git clone https://github.com/ngcloudsec/threat-db.git
pip install poetry
poetry install
poetry run threat_db_admin --init --dgraph-host localhost:9080 --graphql-host http://localhost:8080/graphql
poetry run threat_db_admin --create-root-user --dgraph-host localhost:9080 --graphql-host http://localhost:8080/graphql
```

Copy the user id and password from the logs.

## Import data

```
threat_db --data-dir
```

When invoked with docker compose, any json file present in the directory `THREATDB_DATA_DIR` would be imported automatically.

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
