import os

import threat_db.loader as loader


def test_get_pkg_vulns():
    parsed_obj = loader.get_pkg_vulns_json(
        os.path.join(
            os.path.dirname(__file__), "data", "NodeGoat", "sbom-nodejs.vex.json"
        )
    )
    assert (
        parsed_obj["serial_number"] == "urn:uuid:25223366-1379-41f4-8abf-3a4e11d6548f"
    )
    assert parsed_obj["metadata"]
    assert len(parsed_obj["components"]) == 1080
    assert len(parsed_obj["services"]) == 0
    assert len(parsed_obj["vulnerabilities"]) == 99

    parsed_obj = loader.get_pkg_vulns_json(
        os.path.join(
            os.path.dirname(__file__), "data", "NodeGoat", "sbom-yaml-manifest.vex.json"
        )
    )
    assert (
        parsed_obj["serial_number"] == "urn:uuid:1a1ffcb3-2c26-43af-8032-d312627ab9f8"
    )
    assert parsed_obj["metadata"]
    assert len(parsed_obj["components"]) == 207
    assert len(parsed_obj["services"]) == 2
    assert len(parsed_obj["vulnerabilities"]) == 11
