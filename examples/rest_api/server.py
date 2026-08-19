"""Intentionally vulnerable demo API.

This little FastAPI app exists only so you can watch overstep light up. It ships
three deliberately broken authorization behaviours:

* ``GET /users/{id}``   — any authenticated user can read any profile (BOLA).
* ``GET /admin/users``  — no role check, so a plain user hits it (BFLA / privesc).
* ``DELETE /users/{id}``— any authenticated user can delete anyone (BOLA + write).

Do not use any of this as a reference for real code.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="overstep demo API (vulnerable)")

# token -> (user_id, role)
TOKENS = {
    "alice-token": ("u1", "user"),
    "bob-token": ("u2", "user"),
    "admin-token": ("u9", "admin"),
}

USERS = {
    "u1": {"id": "u1", "name": "Alice", "email": "alice@example.com"},
    "u2": {"id": "u2", "name": "Bob", "email": "bob@example.com"},
    "u9": {"id": "u9", "name": "Root", "email": "root@example.com"},
}


def _caller(authorization: str | None):
    if not authorization:
        return None
    token = authorization.split(" ", 1)[1] if " " in authorization else authorization
    return TOKENS.get(token)


def _require_auth(authorization: str | None):
    caller = _caller(authorization)
    if caller is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return caller


@app.get("/users/{id}")
def get_user(id: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    # VULN (BOLA): never checks that id belongs to the caller.
    if id in USERS:
        return USERS[id]
    raise HTTPException(status_code=404, detail="Not found")


@app.delete("/users/{id}")
def delete_user(id: str, authorization: str | None = Header(default=None)):
    _require_auth(authorization)
    # VULN: deleting is an admin-only function, but any authenticated user gets
    # through here. Kept as a no-op (we don't actually mutate USERS) so the demo
    # stays deterministic across concurrent runs — the 200 is what matters.
    return {"deleted": id}


@app.get("/admin/users")
def admin_list_users(authorization: str | None = Header(default=None)):
    # VULN (BFLA / privilege escalation): should require the admin role, doesn't.
    _require_auth(authorization)
    return {"users": list(USERS.values())}
