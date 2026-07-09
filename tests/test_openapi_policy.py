"""Tests for inferring roles and a starter policy from OpenAPI security schemes."""
import yaml

from overstep.loaders.openapi import scaffold_matrix

_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "demo", "version": "1"},
    "components": {
        "securitySchemes": {
            "oauth": {
                "type": "oauth2",
                "flows": {
                    "authorizationCode": {
                        "scopes": {
                            "user": "regular user",
                            "admin": "administrator",
                        }
                    }
                },
            }
        }
    },
    "paths": {
        "/users/{id}": {
            "get": {
                "summary": "read a user",
                "security": [{"oauth": ["user"]}],
            }
        },
        "/admin/users": {
            "get": {
                "summary": "list all users",
                "security": [{"oauth": ["admin"]}],
            }
        },
        "/public/health": {
            "get": {"summary": "health check"}  # no security -> anonymous
        },
    },
}


def _scaffold(tmp_path, spec=_SPEC):
    p = tmp_path / "openapi.yaml"
    p.write_text(yaml.safe_dump(spec))
    return scaffold_matrix(str(p))


def test_roles_inferred_from_scopes(tmp_path):
    doc = yaml.safe_load(_scaffold(tmp_path))
    # anonymous is always present; declared scopes become roles, least->most.
    assert "anonymous" in doc["roles"]
    assert "user" in doc["roles"]
    assert "admin" in doc["roles"]
    assert doc["roles"].index("user") < doc["roles"].index("admin")


def test_policy_block_generated_from_required_scopes(tmp_path):
    doc = yaml.safe_load(_scaffold(tmp_path))
    policy = doc["policy"]
    # /users/{id} required the "user" scope.
    get_users = next(k for k in policy if k.startswith("get_users"))
    roles = [rule["role"] for rule in policy[get_users]["allow"]]
    assert "user" in roles
    # object resource with an owning scope defaults to own-scope for the user role.
    user_rule = next(r for r in policy[get_users]["allow"] if r["role"] == "user")
    assert user_rule["scope"] == "own"


def test_admin_endpoint_restricted_to_admin(tmp_path):
    doc = yaml.safe_load(_scaffold(tmp_path))
    admin_res = next(k for k in doc["policy"] if "admin_users" in k)
    roles = [rule["role"] for rule in doc["policy"][admin_res]["allow"]]
    assert roles == ["admin"]


def test_unsecured_endpoint_has_no_allow_rules_or_anonymous(tmp_path):
    doc = yaml.safe_load(_scaffold(tmp_path))
    health = next(k for k in doc["policy"] if "public_health" in k)
    # No declared security -> allow anonymous (public).
    roles = [rule["role"] for rule in doc["policy"][health]["allow"]]
    assert roles == ["anonymous"]


def test_scaffold_still_emits_resources(tmp_path):
    doc = yaml.safe_load(_scaffold(tmp_path))
    names = {r["name"] for r in doc["resources"]}
    assert any(n.startswith("get_users") for n in names)
    assert any("admin_users" in n for n in names)
