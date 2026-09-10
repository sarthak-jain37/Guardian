# Guardian

Guardian is a Kubernetes RBAC monitoring project designed to detect changes to Role-Based Access Control (RBAC) configurations and present those changes for review.

The project monitors Kubernetes audit events, maintains an RBAC baseline, detects differences between the expected and current RBAC state, stores detected drift events, and exposes them through a FastAPI backend and Streamlit frontend.

## Current Project Structure

```text
Guardian/
├── backend/
│   └── app/
│       ├── api/
│       │   └── routes/
│       │       ├── dangerous_permissions.py
│       │       └── output.py
│       │
│       ├── core/
│       │   └── config.py
│       │
│       ├── services/
│       │   ├── audit_collector.py
│       │   ├── event_processor.py
│       │   ├── kubernetes_service.py
│       │   ├── permission_scanner.py
│       │   ├── redis_service.py
│       │   └── script_runner.py
│       │
│       ├── workers/
│       │   └── worker.py
│       │
│       └── main.py
│
├── frontend/
│   └── ...
│
├── scripts/
│   ├── apply_script.py
│   └── modify_script.py
│
├── .env
├── pyproject.toml
├── uv.lock
└── README.md
```

## Current Architecture

The current processing pipeline works as follows:

```text
Kubernetes Audit Logs
        ↓
   Audit Collector
        ↓
      Worker
        ↓
  Event Processor
        ↓
   ┌───────────────┐
   │               │
   ▼               ▼
Apply Event    Modify Event
   │               │
   ▼               ▼
Update        Compare Baseline
Baseline      and Current State
   │               │
   ▼               ▼
 Redis        Drift Detection
                   │
                   ▼
             Redis Event Queue
                   │
                   ▼
                FastAPI
                   │
                   ▼
           Streamlit Frontend
```

## Event Processing

The background worker continuously checks for Kubernetes audit events and passes them to the event processor.

Events are currently divided into two groups.

### Apply Events

* `kubectl-client-side-apply`
* `kubectl-server-side-apply`

When a new apply event is detected, Guardian retrieves the current RBAC state from Kubernetes and stores it as the baseline.

### Modify Events

* `kubectl-edit`
* `kubectl-create`
* `kubectl-patch`

When a new modification event is detected, Guardian retrieves the stored baseline and compares it with the current RBAC state.

If differences are found, the detected RBAC drift is stored as an event.

## RBAC State Collection

Guardian currently collects the following Kubernetes resources:

* Roles
* ClusterRoles
* RoleBindings
* ClusterRoleBindings
* ServiceAccounts

The Kubernetes API objects are sanitized before being used for comparison.

## Baseline and Drift Detection

Guardian maintains two RBAC states:

* **Baseline State** — the expected RBAC configuration.
* **Current State** — the current RBAC configuration retrieved from the Kubernetes cluster.

The states are compared using `DeepDiff`.

## Redis Storage

Redis is currently used for several parts of the system.

### Processed Event Timestamps

Guardian stores the last processed timestamp for:

* Apply events
* Modify events

This prevents the same audit events from being processed repeatedly.

### RBAC State

Redis stores:

* The RBAC baseline
* The current RBAC state

### Drift Events

Detected RBAC differences are stored as events in a Redis list.

Each event currently contains:

* A unique event ID
* Detection timestamp
* RBAC diff
* LLM analysis output

## Backend

The backend is built using FastAPI.

The application is responsible for:

* Initializing the Kubernetes client
* Connecting to Redis
* Starting the background worker
* Processing Kubernetes audit events
* Exposing stored drift events through API endpoints

The application uses FastAPI lifespan management to initialize and clean up shared resources.


## Frontend

Guardian includes a Streamlit frontend that retrieves drift events from the FastAPI backend.

The dashboard currently displays:

* RBAC differences
* LLM-generated analysis


## LLM Analysis

Guardian includes a local LLM analysis layer.

The LLM is instructed to:

* Analyze only the provided document
* Avoid inventing information
* Avoid assuming facts not present in the input
* Avoid adding information not present in the document

The LLM output is stored alongside the detected RBAC drift event.


## Setup

### Prerequisites

Ensure you have the following installed:

* **Docker** (running daemon)
* **Kind** (v0.20+) & **kubectl**
* **Redis** (or Valkey) running locally on port `6379`
* **Python 3.11** & **uv** (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

### 1. Install Dependencies

This project uses `uv`.

```bash
uv sync
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Ensure `.env` matches your local setup:

```env
REDIS_URL=redis://localhost:6379/0
BACKEND_URL=http://127.0.0.1:8000
POLLING_INTERVAL=10
MODEL_PATH=/home/dionysus/models/Qwen2.5-7B-Instruct-Q4_K_M.gguf
KUBERNETES_AUDIT_LOG_PATH=/tmp/guardian-audit/audit.log
```

### 3. Download the Local LLM (GGUF)

Download the Qwen 2.5 7B Instruct GGUF model:

```bash
mkdir -p ~/models
curl -L -o ~/models/Qwen2.5-7B-Instruct-Q4_K_M.gguf \
  https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-Q4_K_M.gguf
```

Update `MODEL_PATH` in `.env` to point to the downloaded file.

### 4. Start Redis

```bash
sudo systemctl start redis  # or redis-server &
```

Verify with `redis-cli ping` (should return `PONG`).

### 5. Start the Kind Cluster with Audit Logging

For local development, you can use a local Kubernetes environment such as Kind or Minikube. 

If using the provided Kind cluster configuration (`k8s/kind-config.yaml`):
```bash
kind create cluster --config k8s/kind-config.yaml
```

> **Note for Linux & WSL2 users:**  
> When Kind runs in Docker on Linux, the Kubernetes API server writes audit logs with root-only permissions (`0600`). To allow the Guardian backend worker to read audit events, grant read permissions:
> ```bash
> sudo chmod 755 /tmp/guardian-audit && sudo chmod 644 /tmp/guardian-audit/audit.log
> ```

### 6. Run the Backend

From the project root:

```bash
uv run uvicorn backend.app.main:app --reload --port 8000
```

On boot, the backend automatically connects to Kubernetes, runs an initial security scan for dangerous permissions, and starts the background audit log worker.

### 7. Run the Frontend

Start the Streamlit dashboard in a separate terminal:

```bash
uv run streamlit run frontend/main.py
```

Open `http://localhost:8501` to view the live dashboard.

---

## Triggering Demo & Drift Events

To test live baseline creation and drift detection:

### 1. Establish Baseline (Apply Event)

Create a sample manifest `demo-role.yaml` and apply it:

```bash
cat << 'EOF' > demo-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
EOF

kubectl apply -f demo-role.yaml
```

The worker detects the `kubectl-apply` event and seeds the RBAC baseline in Redis.

### 2. Introduce RBAC Drift (Modify Event)

Edit the role to grant elevated privileges:

Option A: Run with KUBE_EDITOR=nano (or KUBE_EDITOR=vim):

```bash
KUBE_EDITOR=nano kubectl edit role test-role -n default
```

Add `"secrets"` to resources or `"impersonate"` to verbs, then save and exit.

Option B: 1-Line Command (No editor needed!)
Run this single kubectl patch command to instantly add secrets to test-role:

```bash
kubectl patch role test-role -n default --type='json' \
  -p='[{"op": "add", "path": "/rules/0/resources/-", "value": "secrets"}]'
```

### 3. Review Live Results

Within 10 seconds:
1. The backend worker extracts the diff using DeepDiff.
2. The local Qwen LLM analyzes the security impact of the modification.
3. The live drift event, diff cards, and LLM summary appear on the Streamlit dashboard at `http://localhost:8501`.

### 4. Reset and Rerun the Demo

To clear the demo and start fresh:

```bash
# 1. Delete the test role from Kubernetes
kubectl delete role test-role -n default

# 2. Reset drift events in Redis
redis-cli del rbac:drift:events
```

(Or redis-cli flushall to wipe everything and restart the backend).


