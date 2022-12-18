#!/usr/bin/env bash
export DGRAPH_API_KEY=changeme
poetry run threat_db_admin --init --dgraph-host localhost:9080 --graphql-host http://localhost:8080/graphql
sleep 60
poetry run threat_db_admin --create-root-user --dgraph-host localhost:9080 --graphql-host http://localhost:8080/graphql
