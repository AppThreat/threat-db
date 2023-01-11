import os
import re
from tempfile import SpooledTemporaryFile

import orjson

import threat_db.graphclient as graph_client
from threat_db.logger import LOG
from threat_db.utils import find_files, parse_purl, safe_remove

lic_symbol_regex = re.compile(r"[\(\)\,]")


def cleanup_license_string(license_str):
    """
    Method to cleanup license string by removing problematic symbols and making certain keywords consistent
    :param license_str: String to clean up
    :return: Cleaned up version
    """
    if not license_str:
        license_str = ""
    license_str = (
        license_str.replace(" / ", " OR ")
        .replace("/", " OR ")
        .replace(" & ", " OR ")
        .replace("&", " OR ")
    )
    license_str = lic_symbol_regex.sub("", license_str)
    return license_str.upper()


def get_pkg_vulns_json(jsonfile):
    """Method to extract packages from a bom json file"""
    if not os.path.exists(jsonfile):
        return {}
    with open(jsonfile) as fp:
        try:
            bom_data = orjson.loads(fp.read())
            if bom_data:
                return get_pkg_vulns_from_bom(bom_data)
        except Exception:
            return {}


def get_pkg_vulns_from_bom(bom_data):
    components = []
    serial_number = None
    metadata = {}
    metadata = bom_data.get("metadata")
    vulnerabilities = []
    added_vkeys = {}
    if bom_data.get("components"):
        serial_number = bom_data.get("serialNumber", "")
        for comp in bom_data.get("components"):
            licenses = []
            vendor = comp.get("group")
            if not vendor:
                vendor = ""
            if comp.get("licenses"):
                for lic in comp.get("licenses"):
                    license_obj = lic
                    # licenses has list of dict with either license or expression as key
                    # Only license is supported for now
                    if lic.get("license"):
                        license_obj = lic.get("license")
                    if license_obj.get("id"):
                        licenses.append(license_obj.get("id"))
                    elif license_obj.get("name"):
                        licenses.append(cleanup_license_string(license_obj.get("name")))
            purl = comp.get("purl")
            type = ""
            subpath = ""
            qualifiers = {}
            repo_url = ""
            download_url = ""
            if purl:
                purl_obj = parse_purl(purl)
                type = purl_obj.get("type", "")
                subpath = purl_obj.get("subpath", "")
                qualifiers = purl_obj.get("qualifiers", {})
                repo_url = purl_obj.get("repo_url", "")
                download_url = purl_obj.get("download_url", "")
            fcomp = {
                **comp,
                "isRoot": False,
                "bomRef": comp.get("bom-ref"),
                "ctype": type,
                "subPath": subpath,
                "repoUrl": repo_url,
                "downloadUrl": download_url,
                "qualifiers": qualifiers,
                "vendor": vendor,
                "licenses": licenses,
                "appearsIn": [{"serialNumber": serial_number}],
            }
            del fcomp["bom-ref"]
            components.append(fcomp)
        for avuln in bom_data.get("vulnerabilities", []):
            bomRef = avuln.get("bom-ref")
            if added_vkeys.get(bomRef):
                continue
            affects = []
            version = ""
            fix_version = ""
            severity = "none"
            cvss_score = 0
            for ac in avuln.get("affects", []):
                affects.append({"purl": ac.get("ref")})
                for ver in ac.get("versions"):
                    if ver.get("status") == "affected":
                        version = ver.get("version")
                    if ver.get("status") == "unaffected":
                        fix_version = ver.get("version")
            if avuln.get("ratings"):
                for ar in avuln.get("ratings"):
                    if ar.get("method") == "CVSSv31":
                        severity = ar.get("severity")
                        cvss_score = ar.get("score")
            fvuln = {
                **avuln,
                "bomRef": bomRef,
                "affects": affects,
                "version": version,
                "fix_version": fix_version,
                "severity": severity,
                "cvss_score": cvss_score,
            }
            del fvuln["bom-ref"]
            vulnerabilities.append(fvuln)
            added_vkeys[bomRef] = True
    return {
        "serial_number": serial_number,
        "metadata": metadata,
        "components": components,
        "services": bom_data.get("services", []),
        "vulnerabilities": vulnerabilities,
        "bom_data": bom_data,
    }


def process_vex(client, data_dir, remove_on_success=False):
    json_files = find_files(data_dir, ".vex.json", False, True)
    for jsonf in json_files:
        success = process_vex_file(client, jsonf)
        if success and remove_on_success:
            safe_remove(jsonf)


def process_vex_file(client, jsonf):
    parsed_obj = {}
    if isinstance(jsonf, SpooledTemporaryFile):
        try:
            parsed_obj = get_pkg_vulns_from_bom(orjson.loads(jsonf.read()))
        except Exception as ex:
            LOG.warn("Exception while converting to json from tempfile")
            LOG.exception(ex)
            return False
    else:
        LOG.debug(f"Processing {jsonf}")
        parsed_obj = get_pkg_vulns_json(jsonf)
    serial_number = parsed_obj.get("serial_number")
    components = parsed_obj.get("components")
    metadata = parsed_obj.get("metadata")
    services = parsed_obj.get("services")
    if serial_number and components:
        LOG.info(
            f"Creating Bom with {len(components)} components and {len(services)} services from {jsonf}"
        )
        root_component = metadata.get("component", None)
        if root_component and root_component.get("purl"):
            root_component["isRoot"] = True
            root_component["bomRef"] = root_component.get("bom-ref")
            root_component["ctype"] = root_component.get("type")
            del root_component["bom-ref"]
        result = graph_client.create_bom(
            client,
            [
                {
                    "serialNumber": serial_number,
                    "metadata": {
                        "timestamp": metadata.get("timestamp").replace("Z", ""),
                        "component": root_component,
                    },
                    "components": components,
                    "services": services,
                    "vulnerabilities": parsed_obj.get("vulnerabilities"),
                }
            ],
        )
        if result and result.get("addBom"):
            LOG.debug(result)
            return True
        else:
            return False
    return True


def start(client, data_dir, remove_on_success=False):
    process_vex(client, data_dir, remove_on_success)
