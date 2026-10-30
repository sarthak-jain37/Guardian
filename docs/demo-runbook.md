# Run the complete Guardian demo

This guide uses **only** the disposable `guardian-release` Kind cluster and its
private `data/pilot/kubeconfig`. Your original cluster/default kubeconfig is left
alone. Workload installation and scenario setup are explicit operator actions;
Guardian remediation always needs a separate human decision.

## Open the pilot already prepared on this laptop

1. Keep Docker running. From the repository root run the three port-forwards in
   separate terminals (restart a forward after its pod is restarted):

   ```bash
   kubectl --kubeconfig data/pilot/kubeconfig -n guardian-system port-forward svc/guardian-dashboard 18501:8501
   kubectl --kubeconfig data/pilot/kubeconfig -n guardian-system port-forward svc/guardian-backend 18000:8000
   kubectl --kubeconfig data/pilot/kubeconfig -n guardian-system port-forward svc/guardian-model-bridge 19434:11434
   ```

2. The pilot model is the already-downloaded **Qwen3.5 4B**, separate from your
   service's older Qwen3 8B. The host-to-pod route uses a real authenticated relay.
   Start the project server in another terminal if it is no longer running:

   ```bash
   OLLAMA_MODELS="$PWD/data/ollama-models" OLLAMA_HOST=172.18.0.1:11435 \
     OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 ollama serve
   ```

   Then start the relay in another terminal:

   ```bash
   .venv/bin/python -m scripts.guardian_model_bridge relay \
     --bridge http://127.0.0.1:19434 --model http://172.18.0.1:11435 \
     --token-file data/pilot/model-bridge.token
   ```

   One running copy of each is enough. The existing system Ollama service can
   instead be used after pulling the exact model and updating the model endpoint/
   digest. Do not assume a host smoke proves the pod can reach it. Run only one
   model evaluation/build at a time on this 16 GB laptop.

3. Open `http://127.0.0.1:18501`, choose **Analysis and review**, and paste the
   contents of `data/pilot/reviewer.token` into the masked token box. Do not share
   or commit it. It is scoped to `guardian-release / guardian-demo`, with a
   24-hour lifetime from setup. Renew expired credentials deliberately using the
   auth CLI and update the existing Secret; do not reuse someone else's token.

4. Select the latest **validator v3** analysis. Old BLOCKED runs are intentionally
   preserved: they show real missing-model, missing-behavior and truncation cases,
   not successful remediations. If no current prepared proposal is available,
   queue a fresh five-minute analysis with:

   ```bash
   .venv/bin/python -m scripts.guardian_acceptance \
     --directory "data/pilot/check-$(date +%Y%m%dT%H%M%S)"
   ```

   This performs actual collection/model/readiness checks and stops before human
   approval. For an interrupted request, use `--resume` with its same output
   directory. In the UI you can also start an analysis with **Observation window
   (minutes) = 5**. Wait for DONE, then queue independent readiness checks. After
   a collector interruption, wait for a genuinely complete recent interval; do
   not edit completeness fields or pretend five minutes is a week.

   To follow the human approval through to its real execution result, add
   `--follow-approval`. After approval, reuse that same directory with `--resume
   --follow-approval`: it reads the existing action and prints its actual receipt,
   rather than preparing another action or reporting approval as false.
   `live_execution_verified: true` means the stored live execution completed and
   passed verification. Independent reproduction is a separate acceptance gate.

5. Inspect the **separate governed action**: exact Role diff, unchanged binding,
   real query window/watermark, UID/version, retained Pod read, pre-change SARs,
   forced admission dry-run, application proofs and residual uncertainties. The
   intended initial candidate removes unused Secret read while preserving actual
   Pod reads. A BLOCKED result is not permission to force this expected candidate.

6. Only when satisfied, choose **Approve exact Role change**, check the residual
   risk acceptance, and make your separate recovery choice (unchecked by default).
   Record the governed decision. The backend rechecks current authority/evidence
   and applies only if all conditions still pass. Execution must start within
   five minutes of approval. A saved preview or readiness check is not an approval.

   The terminal uses the same governed API:

   ```bash
   .venv/bin/python -m scripts.guardian_review list
   .venv/bin/python -m scripts.guardian_review show PROPOSAL_ID
   .venv/bin/python -m scripts.guardian_review decide PROPOSAL_ID --kind approve_remediation --expected-revision REVISION --expected-hash APPROVAL_HASH --accept-residual-risk
   .venv/bin/python -m scripts.guardian_review watch PROPOSAL_ID
   ```

   Replace the uppercase placeholders with the exact values displayed by `show`.
   `decide` also supports rejection, acknowledgement, context requests and baseline
   adoption. Recovery is a separate opt-in using `--recovery-hash` from that review;
   omitting it does not grant recovery authority. No command accepts arbitrary rules.

7. Refresh and inspect the actual receipt: confirmed apply, verification passed,
   first active baseline and outcome notification. Acknowledge the notice; this
   does not pause monitoring. If the outcome is manual/stale/failed, read the
   stored checks and retain that result. Do not patch the Role manually and then
   claim Guardian completed it.

8. Verify the current Role independently:

   ```bash
   kubectl --kubeconfig data/pilot/kubeconfig -n guardian-demo get role pod-reader -o yaml
   kubectl --kubeconfig data/pilot/kubeconfig -n guardian-demo get pods
   ```

   Before your approval its original Pod/Secret grants should still be present.
   After verified narrowing only the approved resulting rules should be present.
   Check the receipt's actual UID/resourceVersion rather than comparing only names.

## Show later drift and the negative routes

After a successful first baseline, explicitly introduce the harmless scenario
addition:

```bash
.venv/bin/python -m scripts.guardian_pilot scenario drift --confirm-disposable
```

This tests the current UID/version and owner label and changes only the owned
Role. It preserves evidence, baseline and decision history. Queue a fresh analysis,
inspect the distinct drift case and make another human decision. Do not run the
scenario before proving the first baseline, or call it baseline remediation.

Use `scenario reset --confirm-disposable` to restore the demonstration's starting
grant set without deleting history. The installer refuses to overwrite an
existing Role. Do not use Helm upgrade to reset the target: the workload is
separate from the application chart.

The CPU recording demo safely exercises reject/adoption, expired/stale/revoked/
paused/incident authority, unknown apply and qualifying recovery/fresh fallback:

```bash
.venv/bin/python -m unittest tests.test_execution tests.test_execution_workspace -v
GUARDIAN_DEMO=$(mktemp -d)
.venv/bin/python -m agents.guardian.demo --directory "$GUARDIAN_DEMO" --skip-tests
```

Label these as recording/synthetic cases. A live recovery drill needs a controlled
real application failure, exact consent, healthy-dependency evidence and verified
restoration. Do not substitute a fake passing harness or deliberately remove a
known-used grant to force a success. The run's source, receipt and classification
are the evidence.

## Reproduce from a clean laptop or approved host

1. Install Docker, Kind, kubectl, Helm 3.19.0, uv and Ollama; have at least 16 GB RAM
   and adequate disk. The tested Kind image is the pinned Kubernetes 1.30.0 digest
   in `scripts.guardian_pilot`; it is a local reproducibility pin, not a current
   supported production-version endorsement. Use the approved maintained lab
   Kubernetes version for submission and rerun the chart/behavior checks.
2. `uv sync --locked --extra verification`, then run the full tests below.
3. Run `guardian_pilot setup`. It creates its named cluster only if absent,
   configures real audit logging, namespaces, unique scoped credentials and archive
   keys. It does not approve remediation or alter your other cluster. Keep the
   private directory; setup will not attach to an unrelated existing cluster
   without its original private kubeconfig.
4. Build/load the runtime and reader images:

   ```bash
   docker build -t guardian:0.2.0-rc.1 .
   docker build -t guardian-pod-reader:0.2.0-rc.1 demo/workloads
   kind load docker-image guardian:0.2.0-rc.1 guardian-pod-reader:0.2.0-rc.1 --name guardian-release
   ```

   Pin the actual loaded reader manifest digest, available with
   `docker exec guardian-release-control-plane crictl images -o json`. For a
   registry image use its actual repository digest. Run
   `guardian_pilot workload --image REPOSITORY@sha256:ACTUAL_DIGEST`; never invent
   a digest or use `latest`. For locally loaded images, tag that manifest digest
   reference in the node's containerd image store if required by your Kind version.
5. Install the default-disabled chart using `values-dev.yaml` and actual reachable
   model endpoint/digest. If the firewall requires the bridge, generate a strong
   token into a private file and create `guardian-model-bridge` with key
   `bridge.token`; enable its chart option and run the relay as above. Do not put
   secret values into Helm values.
6. Run `guardian_pilot execution-policy` to bind actual Role/SA/workload/image IDs
   and real runner artifact hashes. Explicitly upgrade the isolated pilot with
   `execution.enabled=true`. The backend alone receives the named-Role grant;
   this still does not authorize any human action. Collect five complete minutes
   and follow the review steps above.

Use `deployment.md` for the full Helm command, storage/key custody, compatible
upgrade, scheduled backup and fail-closed restore procedure. `evaluation.md`
contains exact frozen A/B commands and the two-human-label-review requirement.

## Check everything before presenting

```bash
.venv/bin/python -m unittest discover -s tests -q
uv lock --check --offline
helm lint deploy/helm/guardian
helm template guardian deploy/helm/guardian --namespace guardian-system
kubectl --kubeconfig data/pilot/kubeconfig -n guardian-system get pods
kubectl --kubeconfig data/pilot/kubeconfig -n guardian-system get pvc
```

Record the release commit, image/model digests, current live run/decision/receipt
IDs, actual outcomes and failures. Keep an independently reproduced lab install,
measured restore/capacity report and clearly labeled recorded-demo fallback.
The final user acceptance checklist is in `project-report.md`; screenshots alone
are not a passing integration result.
