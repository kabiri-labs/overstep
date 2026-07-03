# overstep × OWASP crAPI

This example runs overstep against **OWASP crAPI**, an intentionally-vulnerable
API, so you can see real BOLA / BFLA findings end to end.

> We do not redistribute crAPI here — use the official images.

## Steps

1. **Run crAPI** (see the official instructions):
   ```bash
   git clone https://github.com/OWASP/crAPI.git
   cd crAPI
   docker compose up -d
   ```

2. **Create two users** (say Alice and Bob) through the web UI or REST API and
   grab their **JWTs**. The browser DevTools Network tab shows the
   `Authorization: Bearer <JWT>` header after login.

3. **Fill in `matrix.yaml`**:
   - Paste the two JWTs into the `subjects` block.
   - Set each subject's `user_id` attribute to the id crAPI assigns them (it's in
     the JWT claims).
   - Adjust the resource paths to match your crAPI version. If you're not sure
     which endpoints exist, scaffold a starter list from a HAR capture:
     ```bash
     # DevTools -> Network -> Preserve log -> save as traffic.har
     overstep scaffold traffic.har --fmt har > resources.snippet.yaml
     ```

4. **Run overstep**:
   ```bash
   overstep run examples/crapi/matrix.yaml --out out
   ```

5. **Review findings** in `out/report.html` (human) or `out/findings.json` /
   `out/overstep.sarif` (machine / CI).

## Wiring it into CI

Snapshot the authorization surface once you've triaged the known findings, then
fail the pipeline only when something *changes*:

```bash
overstep snapshot examples/crapi/matrix.yaml --out baseline.json
# later, on every PR:
overstep run examples/crapi/matrix.yaml --baseline baseline.json --fail-on drift
```

## Notes

- Start read-only (GET resources) before adding write operations to the matrix.
- Keep `matrix.yaml` and `baseline.json` in version control so authorization is
  reviewed like any other code.
