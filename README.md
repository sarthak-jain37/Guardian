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
│       │       └── output.py
│       │
│       ├── core/
│       │   └── config.py
│       │
│       ├── services/
│       │   ├── audit_collector.py
│       │   ├── event_processor.py
│       │   ├── kubernetes_service.py
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

### 1. Install Dependencies

This project uses `uv`.

```bash
uv sync
```

### 2. Configure Environment Variables

Copy .env.example to .env and configure the required environment variables.

Additional configuration may be required depending on the Kubernetes environment and local LLM setup.

### 3. Start Redis

Make sure Redis is running.

### 4. Start a Kubernetes Cluster

Guardian requires access to a running Kubernetes cluster.

For local development, you can use a local Kubernetes environment such as kind or Minikube. Ensure your Kubernetes configuration is accessible through your current kubeconfig or through in-cluster configuration.


### 5. Run the Backend

From the project root:

```bash
uv run uvicorn backend.app.main:app --reload --port 8000
```


### 6. Run the Frontend

Start the Streamlit application from the project root:

```bash
uv run streamlit run frontend/app.py
```

The frontend communicates with the FastAPI backend to retrieve stored drift events.


