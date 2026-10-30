# Evidence and history (Phase 2)

The independent collector reads Kubernetes audit JSON lines; inference never runs
in its collection loop. Start the backend and collector on the same host and
private persistent SQLite volume. No command below applies cluster resources.

Use `k8s/guardian-usage-audit-policy.yaml` as the reviewed pilot policy, mounted by
the cluster operator as the **actual** API-server audit policy. Existing Kind
clusters must be configured separately; copying the file does not enable audit.
Create a private source declaration matching `CollectionPolicy` with an exact
cluster ID, source ID, namespace, resource scope mapping, policy reference, SHA256
of the actual policy bytes, maximum lag, and operator completeness attestation.
Use a new source ID when the policy changes. Never assert completeness for an
unverified export or a policy that excludes relevant requests/stages.

```bash
.venv/bin/python -m scripts.guardian_archive_keys --help
.venv/bin/python -m scripts.guardian_collect --help
```

Generate a key registry on private persistent storage with the key CLI, then run
the collector with `--database`, `--source-policy`, `--audit-policy`, `--audit-log`,
`--archive-directory` and `--archive-keys`. The backend uses the same database;
set `GUARDIAN_ARCHIVE_DIRECTORY` and `GUARDIAN_ARCHIVE_KEYS` there for retrieval.
Keep all historical key IDs when rotating. Backup both ciphertext and keys through
separate protected operator procedures; external durable copy and measured
backup/restore acceptance belong to Phase 5.

Requests are deduplicated across stages and sources by cluster/auditID. Outcome
corrections update the original request hour; old published summaries stay
immutable. Successful completion, authorized errors, authorized incomplete,
denied and unknown are separate. Long watches crossing the start boundary are
reported separately. Exact half-open queries clip the first/last hour and carry
explicit zero buckets alongside independent coverage. Missing or recreated
identity, policy exclusion, malformed records, truncation and source loss prevent
covered non-use claims. A 403/404 alone does not establish authorization.

Coverage requires the declared policy, attestation, persisted cursor, bounded
lateness assumption and consecutive *captured* registered audit probes. A `/version`
HTTP response alone does not prove collection health. This is declared-source
coverage under those assumptions, not a proof that an unobserved external source
has no loss. A silent policy/source failure stops the processed-through watermark.

Archives seal hourly or at 100 MiB, encrypt compressed original records, read back
and verify before acknowledging the catalog, and retain parser/policy/coverage
provenance. Default raw archive retention is 90 days (365 optional); hot raw is
7 days and request index is 90 days. `--prune` must be explicitly enabled; only
acknowledged readable raw segments can leave hot storage. Case pins protect both
request records and quiet-hour coverage. Expiry creates tombstones; missing,
corrupt, unavailable-key and expired retrieval are distinct from zero usage.
Queries exceeding restore/index limits are explicitly partial/truncated.

Inventory snapshots preserve UID/resourceVersion, actual bindings, effective
alternate grants, controllers including scaled-to-zero and scheduled workloads,
and image digest uncertainty. Consumer discovery completeness is restricted to
explicit operator-controlled namespaces (`GUARDIAN_CONTROLLED_NAMESPACES`);
unknown/off-cluster/shared consumers block narrowing. Capturing inventory never
claims startup/restart behaviors were exercised. Semantic hashes include binding
and rule restrictions while execution identity remains a separate UID/version
envelope. Legacy hashes are incompatible with semantic v2, not new authority.

Scoped authenticated endpoints: `POST /evidence/usage`, `GET /evidence/roles`,
`GET /evidence/snapshots/{id}`, `POST /evidence/archive-query`. They expose normalized
evidence, never archive paths, credentials or encryption keys. No endpoint lets a
model or reviewer assert collection completeness. All current evidence tests are
local fixtures; real collection capacity, external copy and live policy acceptance
remain deployment checks.
