import os
from datetime import timedelta
from tempfile import TemporaryDirectory

from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from uwsgidecorators import filemon

import threat_db.graphclient as graph_client
import threat_db.loader as data_loader
from threat_db.config import JWT_ACCESS_TOKEN_EXPIRES_HOURS
from threat_db.logger import LOG

MAX_CONTENT_LENGTH = 10 * 1000 * 1000  # 10 Mb
ALLOWED_EXTENSIONS = ["json", "jsonl"]

DGRAPH_GRAPHQL_HOST = os.getenv("DGRAPH_GRAPHQL_HOST", "http://alpha:8080/graphql")
DGRAPH_RPC_HOST = os.getenv("DGRAPH_RPC_HOST", "alpha:9080")
THREATDB_DATA_DIR = os.getenv("THREATDB_DATA_DIR")

headers = {"Content-Type": "application/json", "Accept-Encoding": "gzip"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
if os.getenv("JWT_SECRET_KEY"):
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
else:
    app.config["JWT_SECRET_KEY"] = os.urandom(64).hex()
app.config["JWT_TOKEN_LOCATION"] = ["headers", "json"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=JWT_ACCESS_TOKEN_EXPIRES_HOURS)
if os.getenv("THREATDB_TMP_DIR"):
    app.config["UPLOAD_FOLDER"] = os.getenv("THREATDB_TMP_DIR")
else:
    app.config["UPLOAD_FOLDER"] = TemporaryDirectory(prefix="threatdb")

jwt = JWTManager(app)

transport, client = graph_client.get(DGRAPH_GRAPHQL_HOST, os.getenv("DGRAPH_API_KEY"))


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/login", methods=["POST"])
def login():
    user_id = request.json.get("username", None)
    password = request.json.get("password", None)
    try:
        auth_res = graph_client.auth_user(client, user_id, password)
        if auth_res:
            access_token = create_access_token(identity=user_id)
            return jsonify(access_token=access_token)
        else:
            return jsonify({"msg": "Invalid user id or password"}), 401
    except Exception:
        return jsonify({"msg": "Invalid user id or password"}), 401


def identity(payload):
    user_id = payload["identity"]
    return user_id


@app.route("/healthcheck")
def healthcheck():
    if graph_client.is_alive(client, DGRAPH_GRAPHQL_HOST):
        return "ok"
    return ""


def process_file(file):
    if file.filename == "":
        return {"success": "false", "message": "Empty file uploaded"}, 500
    if file and not allowed_file(file.filename):
        return {
            "success": "false",
            "message": f"File is not a supported type. Supported types are {', '.join(ALLOWED_EXTENSIONS)}",
        }, 500
    result = data_loader.process_vex_file(client, file.stream)
    return result


if DGRAPH_GRAPHQL_HOST in ("http://alpha:8080/graphql"):

    @app.route("/whoami", methods=["GET"])
    @jwt_required()
    def whoami():
        current_user = get_jwt_identity()
        return jsonify(user=current_user)


@app.route("/import", methods=["POST"])
@jwt_required()
def import_data():
    current_user = get_jwt_identity()
    files = request.files.getlist("file")
    if not files:
        return {
            "success": "false",
            "message": "Upload files to import using the file attribute",
        }, 500
    # check if the post request has the file part
    for uf in files:
        result = process_file(uf)
        if not result:
            return {
                "success": "false",
                "message": "File was not processed successfully",
            }, 500
    return jsonify(success=True)


@app.route("/graphql", methods=["POST"])
@jwt_required()
def proxy_graphql():
    current_user = get_jwt_identity()
    result = graph_client.raw_execute(client, request.json)
    if result:
        return jsonify(data=result)
    return {
        "data": {},
        "errors": [{"message": "No results"}],
    }, 500


if THREATDB_DATA_DIR and os.path.exists(THREATDB_DATA_DIR):
    if os.access(THREATDB_DATA_DIR, os.R_OK):

        @filemon(THREATDB_DATA_DIR)
        def data_drop(signum):
            try:
                data_loader.start(client, THREATDB_DATA_DIR, remove_on_success=True)
            except Exception:
                LOG.debug(
                    f"Error processing the files in {THREATDB_DATA_DIR}. This is usually due to duplicate invocations."
                )

    else:
        LOG.warn(
            f"API server does not have read access to the directory {THREATDB_DATA_DIR}"
        )

    if not os.access(THREATDB_DATA_DIR, os.W_OK):
        LOG.warn(
            f"API server does not have write access to the directory {THREATDB_DATA_DIR}. Any processed file must be therefore removed via other means to avoid duplication."
        )
