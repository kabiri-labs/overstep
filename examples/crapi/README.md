# overstep × OWASP crAPI

This example runs overstep against **OWASP crAPI**, an intentionally-vulnerable
API, so you can see real BOLA / BFLA findings end to end — on both of its
surfaces. [`matrix.yaml`](matrix.yaml) covers the REST gateway and
[`matrix_mcp.yaml`](matrix_mcp.yaml) the MCP server a current crAPI exposes in
front of the same data. Both are keyed to the same vehicles, so the two results
are comparable: the same missing check, reached through two different doors.

> We do not redistribute crAPI here — use the official images.

## 1. Run crAPI

```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker
docker compose up -d
```

The gateway comes up on `http://localhost:8888` and crAPI's own MCP server on
`http://localhost:5500/mcp`. Its `.env` ships `TLS_ENABLED=true`; if you turn
that off, turn it off for the **whole** stack, because the services verify each
other's tokens over the same setting and a half-converted stack answers `500`.

## 2. Create two users and claim their vehicles

Two identities holding genuinely *different* objects are what makes a cross-owner
probe possible, so this part is not optional. crAPI will do it over its own API:

```bash
API=http://localhost:8888
for U in alice bob; do
  curl -s -X POST "$API/identity/api/auth/signup" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$U\",\"email\":\"$U@example.test\",\"number\":\"90090090${#U}\",\"password\":\"Passw0rd!x\"}"
done
```

Log each one in for a JWT:

```bash
curl -s -X POST "$API/identity/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.test","password":"Passw0rd!x"}'
```

Signing up mails each user a VIN and pincode — read them from MailHog at
`http://localhost:8025` — and claiming the vehicle is what gives the account an
object to own:

```bash
curl -s -X POST "$API/identity/api/v2/vehicle/add_vehicle" -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ALICE_JWT" -d '{"vin":"<from the mail>","pincode":"<from the mail>"}'
curl -s "$API/identity/api/v2/vehicle/vehicles" -H "Authorization: Bearer $ALICE_JWT"
```

The `uuid` in that last response is the object id the matrix needs. The seeded
`admin@example.com` / `Admin!123` account already owns one.

## 3. Fill in the matrix

[`matrix.yaml`](matrix.yaml) is written for this flow. Two things to get right:

- **Tokens come from the environment**, as `${CRAPI_ALICE_TOKEN}` and friends.
  Put them in a file and pass `--env-file`; do not paste them into the matrix.
- **Object ids go in `objects:`**, one real vehicle uuid per subject. Do *not*
  reach for `owner_attr: user_id` here — a vehicle is keyed by uuid, not by the
  owner's numeric id, and pointing the two at each other produces a request for
  an object nobody owns. overstep reports that as an `unexpected-deny` rather
  than a finding, which is correct and is also the matrix telling you it is
  wrong.

Adjust the paths to the crAPI version you are running. If you are not sure which
endpoints exist, draft a starter list from a HAR capture:

```bash
# DevTools -> Network -> Preserve log -> save as traffic.har
overstep scaffold traffic.har --fmt har > resources.snippet.yaml
```

## 4. Run it

```bash
overstep validate examples/crapi/matrix.yaml --env-file crapi.env --live
overstep plan     examples/crapi/matrix.yaml --env-file crapi.env
overstep run      examples/crapi/matrix.yaml --env-file crapi.env --out out
```

`validate --live` first: it is one allowed request per subject, and it catches
the expired JWT that would otherwise turn every negative test into a pass for
the wrong reason. Against a current crAPI expect object-level findings on the
vehicle location and function-level findings on the shop's order history, each
**confirmed** — the victim's marker turns up in the response, so data really did
cross the boundary rather than an empty `200` coming back.

Review `out/report.html` (human) or `out/findings.json` / `out/overstep.sarif`
(machine / CI).

## 5. The MCP surface, same instance

crAPI's MCP server fronts the same API, so the same questions have a second door.
[`matrix_mcp.yaml`](matrix_mcp.yaml) asks them, and asks them *identically*: each
resource carries its REST twin's name, reaches the same crAPI route, and uses the
same vehicle uuids. The two runs therefore produce the same `test_id`s, and the
reports can be compared line for line.

Fill in the same three uuids as in step 3, then:

```bash
overstep validate examples/crapi/matrix_mcp.yaml --env-file crapi.env --live
overstep run      examples/crapi/matrix_mcp.yaml --env-file crapi.env --out out-mcp
```

Use a different `--out` than the REST run: reports are cleared from it before
anything is sent, so pointing both runs at one directory leaves you with only
the second — and the comparison is the point.

What that comparison shows on a current crAPI: every finding the REST run
reports comes back through the MCP door with the same `test_id` and the same
class — both `vehicle_location` BOLA findings and both `all_shop_orders`
privilege escalations. The MCP run adds its own: the tool-enumeration probes,
which have no REST equivalent, and the `anon` cases, which get through only
there.

The endpoint is written as `/mcp`. A current crAPI answers that with a `307` to
`/mcp/`, which overstep follows, so either spelling reaches the server.

To see the whole surface rather than these three resources — a current crAPI
exposes 44 tools — draft one from the live server instead:

```bash
overstep scaffold http://localhost:5500/mcp --fmt mcp --server-name crapi \
    --token "$CRAPI_ALICE_TOKEN" > mcp-full.yaml
```

That reads its real tool list and infers which tools are object-level and which
argument owns the object. The policy is still the part only you can write.

Worth knowing before you read the result: crAPI's MCP server authenticates to
crAPI **once**, with a hardcoded admin API key, and then serves every caller with
it. So findings there include an unauthenticated caller reaching tools reserved
for a role — the same defect as the REST BOLA, arriving as a confused deputy.
That is a property of this target, not of the protocol.

## Wiring it into CI

Snapshot the authorization surface once you've triaged the known findings, then
fail the pipeline only when something *changes*:

```bash
overstep snapshot examples/crapi/matrix.yaml --env-file crapi.env --out baseline.json
# later, on every PR:
overstep run examples/crapi/matrix.yaml --env-file crapi.env \
    --baseline baseline.json --fail-on vuln-or-drift
```

Gate on `vuln-or-drift` rather than `drift`: a newly added operation has nothing
in the baseline to differ from, so a drift-only gate goes green on exactly the
case the baseline is for.

## Notes

- Start read-only (GET resources) before adding write operations to the matrix.
  `--read-only` skips mutating verbs, and the summary now names the surfaces it
  skipped so a clean result is not read as covering them.
- Keep `matrix.yaml` and `baseline.json` in version control so authorization is
  reviewed like any other code. Keep the tokens out of both.
- Only test targets you are authorized to test. crAPI on your own machine is one.
