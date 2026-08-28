# Guardian

Guardian is a Kubernetes-based project built around a multi-agent system. The project includes a FastAPI backend that monitors Kubernetes audit events, detects changes, and triggers the appropriate processing pipeline.

## Current Project Structure

```text
Guardian/
├── backend/
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── api/
│       ├── services/
│       ├── workers/
│       └── utils/
│
├── .env
├── pyproject.toml
├── uv.lock
└── README.md
```

## Backend Architecture

The current backend pipeline works like this:

```text
Audit Collector
      ↓
Worker
      ↓
Event Processor
      ↓
Script Runner
      ↓
Redis
```

The worker continuously checks for new audit events. Events are currently divided into two groups:

### Apply Events

* `kubectl-client-side-apply`
* `kubectl-server-side-apply`

These trigger the apply processing script.

### Modify Events

* `kubectl-edit`
* `kubectl-create`
* `kubectl-patch`

These trigger the modify processing script.

Redis is used to store the last processed timestamp for each event group so the same event is not processed repeatedly.

## Current Status

The following backend functionality is currently implemented and tested with mock data:

* FastAPI application setup
* Application lifespan management
* Async Redis connection
* Background worker
* Event polling
* Timestamp comparison
* Apply and modify event grouping
* Redis tracking of processed timestamps
* Mock audit data collection
* Mock script execution

The real Kubernetes audit collector and processing scripts still need to be integrated.

## Setup

### 1. Install dependencies

This project uses `uv`.

```bash
uv sync
```

### 2. Create your environment file

Create a `.env` file in the project root:

```env
REDIS_URL=redis://localhost:6379
```

### 3. Start Redis

Make sure Redis is running locally.

For example:

```bash
redis-server
```

You can verify the Redis connection with:

```bash
redis-cli ping
```

Expected output:

```text
PONG
```

### 4. Run the backend

From the project root:

```bash
uv run uvicorn backend.app.main:app
```

The backend will start at:

```text
http://127.0.0.1:8000
```

## Development

The worker currently checks for audit data every 10 seconds.

The current audit collector and script runner use mock implementations for testing. These should be replaced with the actual Kubernetes audit collector and agent/script logic during integration.

