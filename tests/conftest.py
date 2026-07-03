"""Shared fixtures: a small in-memory matrix used across the test modules."""
import pytest

from overstep.matrix import Matrix


@pytest.fixture
def matrix() -> Matrix:
    return Matrix(
        base_url="http://testserver",
        roles=["anonymous", "user", "admin"],
        subjects=[
            {"name": "alice", "role": "user", "token": "a", "attributes": {"user_id": "u1", "tenant": "t1"}},
            {"name": "bob", "role": "user", "token": "b", "attributes": {"user_id": "u2", "tenant": "t2"}},
            {"name": "root", "role": "admin", "token": "r", "attributes": {"user_id": "u9", "tenant": "t1"}},
            {"name": "anon", "role": "anonymous", "token": None},
        ],
        resources=[
            {
                "name": "get_user",
                "request": {"method": "GET", "path": "/users/{id}"},
                "type": "object",
                "owner_param": "id",
                "owner_attr": "user_id",
            },
            {
                "name": "admin_list",
                "request": {"method": "GET", "path": "/admin/users"},
                "type": "function",
            },
        ],
        policy={
            "get_user": {"allow": [
                {"role": "user", "scope": "own"},
                {"role": "admin", "scope": "any"},
            ]},
            "admin_list": {"allow": [{"role": "admin"}]},
        },
    )
