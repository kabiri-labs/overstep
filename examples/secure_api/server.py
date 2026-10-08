"""A correctly-authorizing demo API — the mirror image of the broken one.

``examples/rest_api`` exists so you can watch overstep light up. This one exists
so you can watch it stay dark *for the right reason*, which is a different claim
and a harder one: a run reports no findings when the target is sound, and also
when nothing ever reached it. Only one of those is worth anything, and the demo
that shows the difference has to be a target that genuinely enforces its policy.

Same three routes and the same matrix as the broken demo. Every check the other
one omits is present here:

* ``GET /users/{id}``    — a user may read only their own profile; an admin may
  read anyone's.
* ``DELETE /users/{id}`` — admin only.
* ``GET /admin/users``   — admin only.

Run it alongside ``examples/secure_api/matrix.yaml`` and the summary is zero
vulnerabilities, the run is conclusive, and every expected-allow test was
allowed — which is what makes the zero mean something.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="overstep demo API (secure)")

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


def _require_auth(authorization: str | None):
    """Resolve the caller, or refuse. Authentication only — see _require below."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ", 1)[1] if " " in authorization else authorization
    caller = TOKENS.get(token)
    if caller is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return caller


@app.get("/users/{id}")
def get_user(id: str, authorization: str | None = Header(default=None)):
    user_id, role = _require_auth(authorization)
    # The check the broken demo omits: the object has to belong to the caller,
    # unless the caller is an admin.
    if role != "admin" and id != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if id not in USERS:
        raise HTTPException(status_code=404, detail="Not found")
    return USERS[id]


@app.delete("/users/{id}")
def delete_user(id: str, authorization: str | None = Header(default=None)):
    _user_id, role = _require_auth(authorization)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    if id not in USERS:
        raise HTTPException(status_code=404, detail="Not found")
    # A no-op, like the broken demo's, so concurrent runs stay deterministic.
    return {"deleted": id}


@app.get("/admin/users")
def admin_list_users(authorization: str | None = Header(default=None)):
    _user_id, role = _require_auth(authorization)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"users": list(USERS.values())}
