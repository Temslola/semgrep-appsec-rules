# semgrep-appsec-rules

Custom [Semgrep](https://semgrep.dev) rules for the vulnerability classes I most
often find by hand during API and web application penetration testing — **BOLA,
insecure JWT verification, mass assignment, missing authorization, and
injection** — so they get caught in code review instead of a report six weeks
later.

Every rule ships with a test fixture containing both a **vulnerable** case and a
**safe** case, so each rule is proven to fire where it should and stay quiet
where it shouldn't.

```
15/15 rules passing
```

## Why these rules

Generic SAST rulesets are good at the mechanical stuff — weak hashes, `eval`,
`shell=True`. They're weak on **authorization**, because authorization bugs are
about missing code rather than dangerous code, and about intent a scanner can't
read.

Those are exactly the bugs that pay in a pentest. Every rule here started as
something I looked for manually:

| Rule | The manual test it automates |
|---|---|
| `query-by-id-without-ownership-check` | Swap an object ID between two accounts and see if the data comes back |
| `jwt-verification-disabled` | Strip the signature, flip `alg` to `none`, replay the token |
| `mass-assignment-from-request-body` | Add `"role": "admin"` to a request body and check whether it sticks |
| `flask-route-missing-auth-decorator` | Hit every endpoint with no session and see what answers |
| `js-mongo-query-from-request-body` | Send `{"$ne": null}` where a string was expected |

## Rules

### Python — `rules/python/`

| Rule ID | Severity | Catches |
|---|---|---|
| `jwt-verification-disabled` | ERROR | `jwt.decode(..., verify=False)` or `options={"verify_signature": False}` |
| `jwt-none-algorithm-accepted` | ERROR | `"none"` present in the `algorithms` allow-list |
| `jwt-decoded-without-key` | WARNING | `jwt.decode(token)` with no key or algorithms |
| `query-by-id-without-ownership-check` | ERROR | `Model.query.get(id)` with no user-scoping filter (BOLA) |
| `flask-route-missing-auth-decorator` | WARNING | Route handlers with no auth decorator |
| `django-view-csrf-exempt` | WARNING | `@csrf_exempt` on a view |
| `mass-assignment-from-request-body` | ERROR | `Model(**request.get_json())` |
| `setattr-loop-over-request-data` | ERROR | `setattr` in a loop over client-controlled keys |
| `sql-query-string-interpolation` | ERROR | f-strings, `%`, `.format()`, or `+` inside `execute()` |
| `os-command-from-request-input` | ERROR | Shell commands built from request data |

### JavaScript / TypeScript — `rules/javascript/`

| Rule ID | Severity | Catches |
|---|---|---|
| `js-jwt-verification-disabled` | ERROR | `jwt.decode()` used where `jwt.verify()` is required |
| `js-jwt-none-algorithm` | ERROR | `"none"` in the `algorithms` array |
| `js-mongo-query-from-request-body` | ERROR | NoSQL operator injection via unvalidated request input |
| `js-object-assign-from-request-body` | ERROR | `Object.assign(obj, req.body)`, `Model.create(req.body)` |
| `js-express-cors-wildcard-with-credentials` | ERROR | `origin: "*"` together with `credentials: true` |

## Usage

```bash
pip install semgrep

# Scan a project with the whole pack
semgrep --config rules/ /path/to/your/code

# Just the authorization rules
semgrep --config rules/python/missing-authorization.yaml /path/to/your/code

# Fail CI on findings
semgrep --config rules/ --error /path/to/your/code

# SARIF for GitHub code scanning
semgrep --config rules/ --sarif --output results.sarif /path/to/your/code
```

Point Semgrep straight at this repo without cloning:

```bash
semgrep --config https://raw.githubusercontent.com/Temslola/semgrep-appsec-rules/main/rules/python/missing-authorization.yaml .
```

## Testing the rules

```bash
semgrep --test --config rules/ tests/
```

Fixtures use Semgrep's annotation convention: a comment marking a line as a
expected finding, or as one that must **not** be flagged. The safe cases matter
as much as the vulnerable ones — a rule that flags correct code gets switched
off by the team within a week, and then it protects nothing.

For example, the BOLA rule fires on this:

```python
order = Order.query.get(order_id)          # flagged
```

but stays silent on this:

```python
order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()   # not flagged
```

## Tuning before you use these in CI

Two rules are intentionally conservative and need adapting to a real codebase:

- **`flask-route-missing-auth-decorator`** recognises `@login_required`,
  `@jwt_required`, `@requires_auth`, and `@auth.login_required`. Add your
  project's decorator names to the `pattern-not` list, or it will flag every
  route.
- **`query-by-id-without-ownership-check`** assumes ownership is expressed as a
  `user_id` filter. If your models scope by `tenant_id`, `org_id`, or a
  repository layer, adjust the `pattern-not-inside` accordingly.

Both are marked `confidence: MEDIUM` in their metadata for this reason. I'd
rather ship a rule that needs one line of tuning than one that quietly misses
the bug class it was written for.

## Known limitations

- Semgrep matches syntax, not data flow. A query scoped to the current user
  three functions away won't be recognised as safe — use `--config` alongside
  Semgrep Pro's taint analysis for that.
- `js-jwt-verification-disabled` flags all `jwt.decode()` use. That is
  deliberate: reading claims before verification is occasionally legitimate, but
  it should be an explicit, reviewed decision rather than an accident.
- These rules complement the Semgrep registry's `p/owasp-top-ten` pack, they
  don't replace it. Run both.

## CI

`.github/workflows/semgrep.yml` runs the rule unit tests on every push and PR,
then scans the repository and uploads SARIF to GitHub code scanning.

## License

MIT — see [LICENSE](LICENSE).
