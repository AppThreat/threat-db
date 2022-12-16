#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import functools

# import orjson
from urllib.parse import quote_plus

import grpc
import pydgraph

from threat_db.logger import LOG

# from threat_db.schema import bom, component, vulns


def catch_db_errors(fn):
    @functools.wraps(fn)
    def caller(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except grpc.RpcError as re:
            LOG.error(
                "Unable to connect to the database. Ensure the hostname is valid and supports grpc connectivity"
            )
        except Exception as ex:
            LOG.exception(ex)

    return caller


# Create a client stub.
@catch_db_errors
def create_client_stub(host, api_key=None):
    if api_key:
        return pydgraph.DgraphClientStub.from_cloud(host, api_key)
    # Handle standalone and localhost invocations
    if ":9080" in host:
        return pydgraph.DgraphClientStub(host)
    creds = grpc.ssl_channel_credentials()
    call_credentials = grpc.metadata_call_credentials(
        lambda context, callback: callback((("authorization", api_key),), None)
    )
    composite_credentials = grpc.composite_channel_credentials(creds, call_credentials)
    return pydgraph.DgraphClientStub(
        host, composite_credentials, options=(("grpc.enable_http_proxy", 0),)
    )


# Create a client.
def create_client(client_stub):
    return pydgraph.DgraphClient(client_stub)


# Drop All - discard all data and start from a clean slate.
@catch_db_errors
def drop_all(client):
    if client:
        return client.alter(pydgraph.Operation(drop_all=True))
    return None


# @catch_db_errors
# def create_schemas(client):
#     client.alter(pydgraph.Operation(schema=component))
#     client.alter(pydgraph.Operation(schema=bom))
#     client.alter(pydgraph.Operation(schema=vulns))


# @catch_db_errors
# def create_data(client, data):
#     txn = client.txn()
#     try:
#         return txn.mutate(set_obj=data, commit_now=True)
#     finally:
#         txn.discard()


# @catch_db_errors
# def create_bom_data(client, bom):
#     txn = client.txn()
#     try:
#         query = """query all($serialNumber:string) {
#             all(func: eq(serialNumber, $serialNumber)) {
#                 C as uid
#                 serialNumber
#             }
#         }
#         """
#         variables = {"$serialNumber": bom.get("serialNumber")}
#         bom["uid"] = "uid(C)"
#         bmutation = txn.create_mutation(set_obj=bom)
#         request = txn.create_request(
#             mutations=[bmutation], query=query, variables=variables, commit_now=True
#         )
#         response = txn.do_request(request)
#         return response
#     finally:
#         txn.discard()


# @catch_db_errors
# def create_component_data(client, comp):
#     txn = client.txn()
#     try:
#         query = """query all($purl:string) {
#             all(func: eq(purl, $purl)) {
#                 C as uid
#                 name
#                 purl
#             }
#         }
#         """
#         variables = {"$purl": comp.get("purl")}
#         comp["uid"] = "uid(C)"
#         cmutation = txn.create_mutation(set_obj=comp)
#         request = txn.create_request(
#             mutations=[cmutation], query=query, variables=variables, commit_now=True
#         )
#         response = txn.do_request(request)
#         return response
#     finally:
#         txn.discard()


# @catch_db_errors
# def create_vuln_data(client, vuln):
#     txn = client.txn()
#     try:
#         # Look for the component based on purl and link it to the vulnerability
#         query = """query all($purl:string) {
#             all(func: eq(purl, $purl)) {
#                 C as uid
#                 name
#                 purl
#             }
#         }
#         """
#         variables = {"$purl": vuln.get("purl")}
#         vuln["components"] = [
#             {
#                 "uid": "uid(C)",
#                 "dgraph.type": "Component",
#             }
#         ]
#         vmutation = txn.create_mutation(set_obj=vuln)
#         request = txn.create_request(
#             mutations=[vmutation],
#             query=query,
#             variables=variables,
#             commit_now=True,
#         )
#         response = txn.do_request(request)
#         # Add the vulnerability to the component
#         if response.json:
#             comp_json = orjson.loads(response.json)
#             comp_all = comp_json.get("all", [])
#             uids = response.uids
#             for cc in comp_all:
#                 if cc.get("uid"):
#                     uid_key = f"uid({vuln.get('id')})"
#                     cmutation = txn.create_mutation(
#                         set_obj={
#                             "vulnerabilities": [
#                                 {
#                                     "uid": f"{uids.get(uid_key)}",
#                                     "dgraph.type": "Vulnerability",
#                                     **vuln,
#                                 }
#                             ],
#                         }
#                     )
#                     resp = txn.create_request(
#                         query="""{
#                             q(func: eq(uid, $uid)) {
#                                 uid
#                                 name
#                             }
#                         }""",
#                         variables={"$uid": cc["uid"]},
#                         mutations=[cmutation],
#                         commit_now=True,
#                     )
#         return response
#     finally:
#         txn.discard()


def get(host, api_key=None):
    client_stub = create_client_stub(host, api_key)
    client = create_client(client_stub)
    return client_stub, client


def close(client_stub):
    if client_stub:
        client_stub.close()
