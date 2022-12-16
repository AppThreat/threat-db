#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os

import threat_db.client as db_client
import threat_db.graphclient as graph_client
import threat_db.loader as data_loader
from threat_db.logger import LOG


def build_args():
    """
    Constructs command line arguments for the threat_db
    """
    parser = argparse.ArgumentParser(
        prog="threat_db",
        description="Modern threat database.",
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
        "--data-dir",
        dest="data_dir",
        default=os.getenv("THREATDB_DATA_DIR"),
        help="Directory to load data from.",
    )
    parser.add_argument(
        "--remove-on-success",
        action="store_true",
        default=False,
        dest="remove_on_success",
        help="Delete data file that are successfully imported.",
    )
    return parser.parse_args()


def main():
    args = build_args()
    _, client = graph_client.get(args.graphql_host, os.getenv("DGRAPH_API_KEY"))
    if args.init:
        # try:
        #     LOG.info("Dropping all data and recreating db schemas")
        #     client_stub, dqlclient = db_client.get(
        #         args.dgraph_grpc_host, os.getenv("DGRAPH_API_KEY")
        #     )
        #     db_client.drop_all(dqlclient)
        #     db_client.close(client_stub)
        # except Exception as ex:
        #     LOG.warn("Unable to drop existing data due to grpc related issues")
        try:
            LOG.info("Dropping all data and recreating db schemas")
            if graph_client.is_alive(client, args.graphql_host):
                graph_client.drop_all(client, args.graphql_host)
                graph_client.create_schemas(client, args.graphql_host)
        except Exception:
            LOG.warn(
                "Unable to create schemas due to issues connecting to the database"
            )
    if args.data_dir:
        LOG.info(f"Importing data from {args.data_dir}")
        data_loader.start(
            client, args.data_dir, remove_on_success=args.remove_on_success
        )

    if client:
        client.close_sync()


if __name__ == "__main__":
    main()
