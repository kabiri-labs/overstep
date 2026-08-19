"""Tests for inferring roles and a starter policy from OpenAPI security schemes."""
import yaml

from overstep.modules.rest.openapi import scaffold_matrix

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


# A spec that protects everything with a plain bearer token and names no scopes
# — the shape of most real API documents.
_BEARER_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "bearer", "version": "1"},
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/admin/users": {"get": {"summary": "list all users"}},
        "/invoices/{invoice_id}": {"get": {"summary": "read an invoice"}},
    },
}

# A spec that never mentions authorization at all — what most generated
# documents (FastAPI, Flask) look like out of the box.
_SILENT_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "silent", "version": "1"},
    "paths": {
        "/admin/tenants": {"get": {"summary": "list tenants"}},
        "/invoices/{invoice_id}": {"get": {"summary": "read an invoice"}},
    },
}


def test_scope_less_security_is_not_treated_as_public(tmp_path):
    """`security: [{bearerAuth: []}]` requires a credential and names no scope.
    Reading that as "public" made every endpoint allow anonymous, which emits
    zero negative tests."""
    doc = yaml.safe_load(_scaffold(tmp_path, _BEARER_SPEC))

    for resource, rules in doc["policy"].items():
        roles = [rule["role"] for rule in rules["allow"]]
        assert "anonymous" not in roles, f"{resource} was declared public"
        assert "user" in roles


def test_scope_less_object_still_defaults_to_owner_scope(tmp_path):
    doc = yaml.safe_load(_scaffold(tmp_path, _BEARER_SPEC))
    invoice = next(k for k in doc["policy"] if "invoices" in k)

    rules = {r["role"]: r.get("scope") for r in doc["policy"][invoice]["allow"]}

    assert rules["user"] == "own"
    assert rules["admin"] == "any"


def test_a_silent_spec_is_denied_by_default_not_opened_up(tmp_path):
    """Nothing can be inferred, so the guess must over-report rather than
    declare the whole API public."""
    doc = yaml.safe_load(_scaffold(tmp_path, _SILENT_SPEC))

    for resource, rules in doc["policy"].items():
        roles = [rule["role"] for rule in rules["allow"]]
        assert "anonymous" not in roles, f"{resource} was declared public"
    # A function resource is the tightest guess: admin only.
    tenants = next(k for k in doc["policy"] if "tenants" in k)
    assert [r["role"] for r in doc["policy"][tenants]["allow"]] == ["admin"]


def test_a_silent_spec_carries_a_warning_header(tmp_path):
    text = _scaffold(tmp_path, _SILENT_SPEC)

    assert text.startswith("# WARNING:")
    assert "GUESSED" in text
    # The header must not break the document it precedes.
    assert yaml.safe_load(text)["policy"]


def test_the_warn_hook_fires_only_for_a_silent_spec(tmp_path):
    seen = []

    p = tmp_path / "silent.yaml"
    p.write_text(yaml.safe_dump(_SILENT_SPEC))
    scaffold_matrix(str(p), warn=seen.append)
    assert len(seen) == 1 and "declares no authorization" in seen[0]

    q = tmp_path / "documented.yaml"
    q.write_text(yaml.safe_dump(_SPEC))
    scaffold_matrix(str(q), warn=seen.append)
    assert len(seen) == 1, "a documented spec must not warn"


def test_a_documented_spec_emits_no_warning_header(tmp_path):
    assert not _scaffold(tmp_path).startswith("# WARNING")


def test_invented_roles_appear_in_roles_and_subjects(tmp_path):
    """The guessed rules reference roles the spec never named, so the matrix has
    to declare them — otherwise the policy points at subjects that don't exist."""
    doc = yaml.safe_load(_scaffold(tmp_path, _SILENT_SPEC))

    assert doc["roles"] == ["anonymous", "user", "admin"]
    subject_roles = {s["role"] for s in doc["subjects"]}
    assert {"anonymous", "user", "admin"} <= subject_roles
