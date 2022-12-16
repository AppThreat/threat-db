import os

from flask import Flask, request
from uwsgidecorators import filemon, postfork

# import threat_db.client as db_client
import threat_db.graphclient as graph_client
import threat_db.loader as data_loader
from threat_db.logger import LOG

MAX_CONTENT_LENGTH = 10 * 1000 * 1000  # 10 Mb
ALLOWED_EXTENSIONS = ["json", "jsonl"]

DGRAPH_GRAPHQL_HOST = os.getenv(
    "DGRAPH_GRAPHQL_HOST", "http://dgraph-standalone:8080/graphql"
)
DGRAPH_RPC_HOST = os.getenv("DGRAPH_RPC_HOST", "dgraph-standalone:9080")
THREATDB_DATA_DIR = os.getenv("THREATDB_DATA_DIR")

headers = {"Content-Type": "application/json", "Accept-Encoding": "gzip"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

transport, client = graph_client.get(DGRAPH_GRAPHQL_HOST, os.getenv("DGRAPH_API_KEY"))
# client_stub, dqlclient = db_client.get(DGRAPH_RPC_HOST)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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
    result = False
    reconnect_to_db()
    result = data_loader.process_vex_file(client, file.stream)
    if not result:
        return {
            "success": "false",
            "message": "File was not processed successfully",
        }, 500
    return {"success": "true"}


@app.route("/import", methods=["POST"])
def import_data():
    files = request.files
    # check if the post request has the file part
    if "file" in files:
        file = files["file"]
        return process_file(file)
    return {
        "success": "false",
        "message": "Upload files to import using the file attribute",
    }, 500


@postfork
def reconnect_to_db():
    if client and not client.schema:
        graph_client.create_schemas(client, DGRAPH_GRAPHQL_HOST)


if THREATDB_DATA_DIR and os.path.exists(THREATDB_DATA_DIR):
    if os.access(THREATDB_DATA_DIR, os.R_OK):

        @filemon(THREATDB_DATA_DIR)
        def data_drop(signum):
            reconnect_to_db()
            data_loader.start(client, THREATDB_DATA_DIR, remove_on_success=True)

    else:
        LOG.warn(
            f"API server does not have read access to the directory {THREATDB_DATA_DIR}"
        )

    if not os.access(THREATDB_DATA_DIR, os.W_OK):
        LOG.warn(
            f"API server does not have write access to the directory {THREATDB_DATA_DIR}. Any processed file must be therefore removed via other means to avoid duplication."
        )
