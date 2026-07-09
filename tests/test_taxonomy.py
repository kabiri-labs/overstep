"""Tests for CWE / OWASP API Top 10 tagging in the taxonomy and SARIF report."""
import json

from overstep.models import (
    Effect,
    Finding,
    Observation,
    RunResult,
    Variant,
    VulnClass,
)
from overstep.report import get_reporter
from overstep.taxonomy import TAXONOMY, cwe_id, owasp_api, sarif_tags


def test_every_vuln_class_has_a_taxonomy_entry():
    for vc in VulnClass:
        assert vc in TAXONOMY, f"no taxonomy mapping for {vc}"


def test_bola_maps_to_cwe_639_and_api1():
    assert cwe_id(VulnClass.BOLA) == "CWE-639"
    assert owasp_api(VulnClass.BOLA).startswith("API1:2023")


def test_bfla_maps_to_api5():
    assert owasp_api(VulnClass.BFLA).startswith("API5:2023")


def test_bopla_maps_to_api3():
    assert owasp_api(VulnClass.BOPLA).startswith("API3:2023")


def test_sarif_tags_include_external_cwe_and_owasp():
    tags = sarif_tags(VulnClass.BOLA)
    assert "security" in tags
    assert any(t.startswith("external/cwe/cwe-639") for t in tags)
    assert any("API1:2023" in t for t in tags)


def _finding() -> Finding:
    return Finding(
        test_id="get_user::alice::other",
        vuln_class=VulnClass.BOLA,
        severity="high",
        resource="get_user",
        subject="alice",
        role="user",
        method="GET",
        path="/users/u2",
        expected=Effect.DENY,
        observed=Effect.ALLOW,
        status=200,
        variant=Variant.OTHER,
        detail="bola",
        evidence=Observation(test_id="get_user::alice::other", status=200, effect=Effect.ALLOW),
    )


def test_sarif_rule_carries_cwe_and_owasp_metadata(tmp_path):
    result = RunResult(base_url="http://api.test", findings=[_finding()])
    out = tmp_path / "overstep.sarif"
    get_reporter("sarif").write(result, str(out))
    sarif = json.loads(out.read_text())

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    bola = next(r for r in rules if r["id"] == "BOLA")
    assert bola["properties"]["cwe"] == "CWE-639"
    assert bola["properties"]["security-severity"]  # numeric score for GitHub
    assert any(t.startswith("external/cwe/cwe-639") for t in bola["properties"]["tags"])
    assert bola["helpUri"]

    # The result also references the CWE taxonomy relationship.
    res = sarif["runs"][0]["results"][0]
    assert res["properties"]["cwe"] == "CWE-639"
    assert res["properties"]["owasp-api"].startswith("API1:2023")
