#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import uuid
from datetime import datetime

from itsdangerous.url_safe import URLSafeSerializer

import threat_db.graphclient as graph_client
from threat_db.logger import LOG


def build_args():
    """
    Constructs command line arguments for the threat_db
    """
    parser = argparse.ArgumentParser(
        prog="threat_db_admin",
        description="Administration functions for threat database. Only to be used for local development purposes.",
    )
    parser.add_argument(
        "--dgraph-host",
        dest="dgraph_grpc_host",
        default=os.getenv("DGRAPH_RPC_HOST", "localhost:9080"),
        help="DB hostname.",
    )
    parser.add_argument(
        "--graphql-host",
        dest="graphql_host",
        default=os.getenv("DGRAPH_GRAPHQL_HOST", "http://localhost:8080"),
        help="DB hostname.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        default=False,
        dest="init",
        help="Initialize database by dropping all data and recreating the schema.",
    )
    parser.add_argument(
        "--create-root-user",
        action="store_true",
        default=False,
        dest="create_root_user",
        help="Create the initial administrator user.",
    )
    return parser.parse_args()


def create_first_user(client):
    password = URLSafeSerializer(
        secret_key=os.urandom(32).hex(), salt="activate"
    ).dumps(24)
    email = "admin@localhost"
    user_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    role_id = str(uuid.uuid4())
    result = graph_client.create_user(
        client,
        [
            {
                "id": user_id,
                "email": email,
                "password": str(password),
                "fullName": "Local Admin",
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "teams": [
                    {
                        "id": team_id,
                        "name": "Default",
                        "description": "Default team",
                        "tags": ["default", "dev"],
                        "users": [{"id": user_id}],
                        "created": datetime.now().isoformat(),
                        "modified": datetime.now().isoformat(),
                        "disabled": False,
                    }
                ],
                "roles": [
                    {
                        "id": role_id,
                        "user": {"id": user_id},
                        "team": {"id": team_id},
                        "role": "Administrator",
                        "created": datetime.now().isoformat(),
                        "modified": datetime.now().isoformat(),
                        "disabled": False,
                    }
                ],
                "disabled": False,
            }
        ],
    )
    return {
        "result": result,
        "user_id": user_id,
        "email": email,
        "password": password,
    }


def main():
    args = build_args()
    _, client = graph_client.get(args.graphql_host, os.getenv("DGRAPH_API_KEY"))
    if args.init:
        try:
            if graph_client.is_alive(client, args.graphql_host):
                LOG.info("Dropping all data and recreating db schemas")
                graph_client.drop_all(client, args.graphql_host)
                graph_client.create_schemas(client, args.graphql_host)
            else:
                LOG.info(f"Database is not live yet. Check the DB logs for any issues.")
        except Exception:
            LOG.warn(
                "Unable to create schemas due to issues connecting to the database."
            )
    if args.create_root_user:
        try:
            LOG.info("Creating a new admin user for development purposes")
            create_res = create_first_user(client)
            if create_res:
                # Check if authentication works for the new user
                user_id = create_res["user_id"]
                password = create_res["password"]
                auth_res = graph_client.auth_user(client, user_id, password)
                if auth_res:
                    LOG.info(
                        f"An administrator user was created with the id {user_id} and password {password}"
                    )
                    LOG.info(
                        """Use this credential for development purposes only and ensure this account is removed in production.\nTo generate access token for this user, make a POST request to the /login endpoint\n\nexport ACCESS_TOKEN=$(curl -q -X POST %(graphql_host)s/login -d '{"username":"%(user_id)s","password":"%(password)s"}' -H "Content-Type: application/json" | jq -r '.access_token')"""
                        % dict(
                            user_id=user_id,
                            password=password,
                            graphql_host=args.graphql_host,
                        )
                    )
                else:
                    LOG.info(f"Unable to authenticate as the new user {user_id}")
            else:
                LOG.warn(
                    "Unable to create the first administrator user. Check for any errors in the logs."
                )
        except Exception as ex:
            LOG.exception(ex)
            LOG.warn(
                "Unable to create user due to issues connecting to the database. Check if the schema was created successfully."
            )
