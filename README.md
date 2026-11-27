# SentinelX — Intelligent Network Security Monitor

SentinelX is a local network security monitoring dashboard that captures network
traffic, detects suspicious activity, generates security alerts, and visualizes
traffic analytics in real time. It combines a Scapy-based packet capture engine,
a FastAPI backend, a SQLite or PostgreSQL database, and a responsive React
dashboard.

The project is designed as a local educational and portfolio demonstration. It
monitors and detects; it does **not** block, filter, or modify network traffic.

- Repository: <https://github.com/prelobhp524-arch/SentinelX>

---

## Table of Contents

- [Features](#features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [API Overview](#api-overview)
- [Windows Installation and Setup](#windows-installation-and-setup)
- [Environment Variables](#environment-variables)
- [AbuseIPDB Configuration](#abuseipdb-configuration)
- [Running the Application](#running-the-application)
- [Generating Demo Traffic](#generating-demo-traffic)
- [Seeding Simulated Dashboard Data](#seeding-simulated-dashboard-data)
- [Testing](#testing)
- [Limitations](#limitations)

---

## Features

### Network Traffic Monitoring
- Live packet capture using Scapy `AsyncSniffer`.
- Supports IPv4 traffic with TCP, UDP, and ICMP protocol identification.
- Records source and destination addresses, ports, packet size, protocol,
  timestamp, and traffic direction (`INBOUND`, `OUTBOUND`, `UNKNOWN`).
- Start and stop capture from the dashboard.
- Lists available network interfaces and allows interface selection.

### Security Alerts and Notifications
- Port scan detection based on unique destination ports within a time window.
  - Rapid scan: 10 or more unique ports within 60 seconds (`HIGH`).
  - Slow scan: 10 or more unique ports within 120 seconds (`MEDIUM`).
- Traffic spike detection: 100 or more packets from one source within 60 seconds
  (`HIGH`).
- Live-capture inbound TCP SYN port scan detection.
- Duplicate active alerts for the same source and alert type are suppressed.
- Alert status workflow: `NEW`, `ACKNOWLEDGED`, `RESOLVED`.
- In-app notification panel for new alerts.
- Optional background IP reputation checks are queued when alerts are created.

### Traffic Analytics
- Overall traffic and alert summary statistics.
- Traffic distribution by protocol.
- Alert distribution by severity.
- Top source IP addresses by traffic volume and suspicious traffic count.

### IP Monitoring and Reputation Lookup
- Top source IP visualization on the dashboard.
- On-demand IP reputation lookup using the AbuseIPDB API.
- Displays normalized reputation data, including abuse confidence score, report
  counts, country, ISP, domain, usage type, and public/whitelisted/Tor flags.
- Risk categories: `UNKNOWN`, `NONE`, `LOW`, `MODERATE`, `HIGH`, `VERY_HIGH`.
- Cache status reporting (`Cached`, `Stale`, `Live`, `Unavailable`).
- Sanitized provider errors that do not expose credentials or raw provider data.
- Configurable cache TTL, timeouts, and rate limits.

### Real-Time Dashboard Updates
- WebSocket endpoint at `/ws` broadcasts:
  - `traffic.created`
  - `alert.created`
  - `alert.updated`
- Dashboard refreshes via WebSocket events and periodic polling fallback.
- WebSocket connection status is shown in the interface.

### Responsive Interface
- Responsive layout built with React and Tailwind CSS.
- Collapsible navigation, responsive cards, tables, charts, and forms.
- Dashboard sections for overview, analytics, IP monitoring, traffic, and alert
  management.

---

## Technology Stack

| Layer | Technologies |
| --- | --- |
| Frontend | React, Vite, Tailwind CSS, Recharts, Axios, Lucide React |
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Database | SQLite (default), PostgreSQL, SQLAlchemy |
| Packet Capture | Scapy |
| Real-Time Updates | WebSocket (FastAPI/Starlette and browser WebSocket API) |
| IP Reputation | AbuseIPDB REST API via `requests` |
| Testing and Quality | pytest, ESLint, Vite production build |

---

## Architecture

```text
Network Interface
       |
       v
Scapy packet capture (backend)
       |
       v
FastAPI API + detection services
       |
       +--> SQLite (traffic, alerts, reputation cache)
       |
       +--> WebSocket broadcasts
       |
       v
React dashboard (Vite + Tailwind CSS)
```

The frontend calls the backend at `http://127.0.0.1:8000` by default. Set
`VITE_API_BASE_URL` for non-local deployments. CORS defaults to the local Vite
development origins (`http://localhost:5173` and `http://127.0.0.1:5173`) and
can be overridden with `CORS_ALLOW_ORIGINS`.

---

## Project Structure

```text
SentinelX/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routers
│   │   ├── core/         # Configuration and database setup
│   │   ├── models/       # SQLAlchemy models
│   │   ├── services/     # Capture, detection, alerts, reputation, WebSocket
│   │   ├── init_db.py    # Database initialization
│   │   ├── seed_demo.py  # Explicit simulated demo data seeder
│   │   └── main.py       # FastAPI application entry point
│   ├── tests/            # Backend test suite
│   ├── requirements.txt
│   └── simulate_traffic.py
├── frontend/
│   ├── src/
│   │   ├── services/api.js
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## API Overview

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service information |
| `GET` | `/health` | Health check |
| `POST` | `/api/traffic/` | Submit a traffic record for analysis |
| `GET` | `/api/traffic/` | List traffic records |
| `GET` | `/api/traffic/{traffic_id}` | Get a single traffic record |
| `GET` | `/api/alerts/` | List security alerts |
| `GET` | `/api/alerts/{alert_id}` | Get a single alert |
| `PATCH` | `/api/alerts/{alert_id}/status` | Update alert status |
| `GET` | `/api/analytics/summary` | Overall statistics |
| `GET` | `/api/analytics/traffic-by-protocol` | Traffic grouped by protocol |
| `GET` | `/api/analytics/alerts-by-severity` | Alerts grouped by severity |
| `GET` | `/api/analytics/top-source-ips?limit=5` | Top source IP addresses |
| `POST` | `/api/capture/start` | Start packet capture |
| `POST` | `/api/capture/stop` | Stop packet capture |
| `GET` | `/api/capture/status` | Current capture status |
| `GET` | `/api/capture/interfaces` | List available interfaces |
| `GET` | `/api/reputation/{ip_address}` | Look up IP reputation |
| `WS` | `/ws` | Real-time event stream |

Interactive API documentation is available from FastAPI at
`http://127.0.0.1:8000/docs` while the backend is running.

---

## Windows Installation and Setup

### Prerequisites

- Windows 10 or Windows 11.
- Python 3.11 or newer (developed and tested with Python 3.14).
- Node.js 20 or newer with npm.
- [Npcap](https://npcap.com/) installed for Scapy packet capture on Windows.
- Administrator privileges for live packet capture.
- Git (optional, for cloning the repository).

> Npcap is required for live capture. The dashboard and API can run without it,
> but starting packet capture may fail.

### 1. Clone the Repository

```powershell
git clone https://github.com/prelobhp524-arch/SentinelX.git
cd SentinelX
```

If you already have the project locally, open PowerShell in the project root.

### 2. Set Up the Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the activation script, either allow it for the current
session or use the batch activator:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

```powershell
.\venv\Scripts\activate.bat
```

### 3. Create the Backend Environment File

Create `backend/.env` with the configuration you need. At minimum, the defaults
work for local development with IP reputation disabled. See
[Environment Variables](#environment-variables) and
[AbuseIPDB Configuration](#abuseipdb-configuration).

The `.env` file is ignored by Git and must never be committed.

### 4. Initialize the Database

From the `backend` directory, with the virtual environment active:

```powershell
python -m app.init_db
```

This creates the tables using the configured `DATABASE_URL`, or
`DATABASE_URL_UNPOOLED` when that optional setting is present. Run it again
after adding new SQLAlchemy models or when the database is missing a table.
Schema creation is not performed automatically on application startup.

### 5. Start the Backend

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend is available at `http://127.0.0.1:8000`. The frontend expects it on
port `8000`.

### 6. Set Up the Frontend

Open a second PowerShell window in the project root:

```powershell
cd frontend
npm install
```

### 7. Start the Frontend

```powershell
npm run dev
```

Open `http://localhost:5173` in your browser.

### 8. Start Packet Capture

1. Run the backend from a terminal with Administrator privileges.
2. Open the dashboard.
3. Select a network interface.
4. Start capture from the dashboard.

If capture cannot start, verify that Npcap is installed, the selected interface
has an IPv4 address, and the terminal has sufficient privileges.

---

## Environment Variables

Backend settings are read from `backend/.env` via Pydantic Settings. All values
are optional unless noted otherwise.

| Variable | Default | Description |
| --- | --- | --- |
| `PROJECT_NAME` | `SentinelX` | Application name |
| `PROJECT_VERSION` | `1.0.0` | Application version |
| `DEBUG` | `False` | Debug flag |
| `SQLALCHEMY_ECHO` | `False` | Log SQL statements when enabled |
| `PUBLIC_DEMO_MODE` | `False` | Reject state-changing API requests and reputation lookups |
| `CORS_ALLOW_ORIGINS` | local Vite origins | Comma-separated list of allowed browser origins |
| `DATABASE_URL` | `sqlite:///./sentinelx.db` | Database connection URL; PostgreSQL is supported |
| `DATABASE_URL_UNPOOLED` | empty | Optional direct PostgreSQL URL used only by `app.init_db` |
| `IP_REPUTATION_ENABLED` | `False` | Enables IP reputation lookups and the background worker |
| `ABUSEIPDB_API_KEY` | empty | AbuseIPDB API key; required for provider lookups |
| `IP_REPUTATION_CACHE_TTL_HOURS` | `24` | Reputation cache lifetime in hours |
| `ABUSEIPDB_TIMEOUT_SECONDS` | `5` | AbuseIPDB request timeout in seconds |
| `IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window in seconds |
| `IP_REPUTATION_RATE_LIMIT_REQUESTS` | `60` | Client request limit per window |
| `IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES` | `5` | Force-refresh limit per client per window |
| `IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS` | `30` | Provider call limit per window |

Example `backend/.env`:

```dotenv
DEBUG=False
SQLALCHEMY_ECHO=False
PUBLIC_DEMO_MODE=False
CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DATABASE_URL=sqlite:///./sentinelx.db

IP_REPUTATION_ENABLED=false
ABUSEIPDB_API_KEY=
IP_REPUTATION_CACHE_TTL_HOURS=24
ABUSEIPDB_TIMEOUT_SECONDS=5
IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS=60
IP_REPUTATION_RATE_LIMIT_REQUESTS=60
IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES=5
IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS=30
```

Use a relative SQLite path only when starting the backend from the `backend`
directory, so the database resolves to `backend/sentinelx.db`.

For PostgreSQL, set `DATABASE_URL` to the application connection string. For
Neon, use the pooled connection string for the application and optionally set
`DATABASE_URL_UNPOOLED` to the direct connection string for `app.init_db`.
Standard `postgres://` and `postgresql://` URLs are normalized to the psycopg 3
driver. Keep `sslmode=require` in the URL when your provider requires TLS.

### Frontend Environment Variables

Vite exposes only variables prefixed with `VITE_`. Configure these at build time
in the frontend host or in a local `.env` file.

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `http://127.0.0.1:8000` | Backend HTTP base URL |
| `VITE_WS_URL` | Derived from `VITE_API_BASE_URL` | Optional explicit WebSocket URL |

When `VITE_WS_URL` is omitted, the dashboard derives `/ws` from the API base URL
and uses `wss://` automatically for HTTPS deployments. Do not put backend
secrets or API keys in frontend environment variables.

For a public demonstration deployment, set `PUBLIC_DEMO_MODE=True` on the
backend. This keeps GET endpoints available for the dashboard while rejecting
writes, capture start/stop, alert updates, and IP reputation lookups.

---

## AbuseIPDB Configuration

IP reputation is **disabled by default**. To enable provider lookups:

1. Create an AbuseIPDB account and generate an API key.
2. Add the key to `backend/.env`:

   ```dotenv
   IP_REPUTATION_ENABLED=true
   ABUSEIPDB_API_KEY=<your-abuseipdb-api-key>
   ```

3. Restart the backend.

Do not place the API key in source code, the frontend, or version control. The
key is read only by the backend and is excluded from settings representations.

When reputation is enabled but no key is configured, the API returns a normal
fallback response with a sanitized `missing_key` provider error rather than
exposing credentials. Provider failures (timeouts, connection errors, rate
limits, invalid responses) are likewise returned as sanitized error categories.

If reputation is disabled, the reputation endpoint responds with HTTP `503` and
the dashboard reports that the service is unavailable.

---

## Running the Application

Use two terminals.

**Terminal 1 — Backend**

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Terminal 2 — Frontend**

```powershell
cd frontend
npm run dev
```

Then open `http://localhost:5173`.

To run packet capture, start the backend from an Administrator terminal and use
the capture controls in the dashboard.

---

## Generating Demo Traffic

With the backend running, the included simulator can generate normal traffic,
a port scan, or a traffic spike through the public API:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python simulate_traffic.py
```

The simulator uses private source addresses for demonstration and sends traffic
to `http://127.0.0.1:8000/api/traffic/`. It does not require live packet capture.

### Seeding Simulated Dashboard Data

`simulate_traffic.py` posts through the public API and is intended for local
interactive use. To populate an empty dashboard with a consistent, recent
dataset, use the explicit seeding command instead. It inserts simulated network
traffic and security alerts directly through the existing SQLAlchemy models and
never runs automatically during application startup.

All seeded alerts are prefixed with `[SIMULATED]`. The seed command also writes
a row to the `demo_seed_runs` table. That marker makes the command idempotent:
running it again is a no-op, and existing real records are never deleted or
updated. No API endpoint is exposed for seeding.

#### Seed the Local SQLite Database

From the `backend` directory with the virtual environment active:

```powershell
python -m app.init_db
python -m app.seed_demo
```

Expected output includes the number of traffic and alert records inserted. A
second run reports that simulated demo data is already present and inserts
nothing.

#### Seed the Neon PostgreSQL Database

Use the same explicit command with the production connection strings in the
process environment. The command prefers `DATABASE_URL_UNPOOLED` when set, then
falls back to `DATABASE_URL`, matching `app.init_db`.

The safest option is the Render Shell for the backend service, where the
environment variables are already configured:

```powershell
python -m app.init_db
python -m app.seed_demo --yes
```

`--yes` is required for any non-SQLite target. It is an explicit production
safety check so a local command cannot silently seed PostgreSQL by accident.

To run it from a local terminal, set the values for the current process only.
Do not put them in source files or commit them:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
$env:DATABASE_URL = Read-Host "Neon pooled DATABASE_URL"
$env:DATABASE_URL_UNPOOLED = Read-Host "Neon direct DATABASE_URL_UNPOOLED"
python -m app.init_db
python -m app.seed_demo --yes
Remove-Item Env:DATABASE_URL
Remove-Item Env:DATABASE_URL_UNPOOLED
```

`DATABASE_URL_UNPOOLED` is optional. If it is not set, the command uses
`DATABASE_URL`. The seed command creates missing tables, including the
`demo_seed_runs` marker table, but does not alter existing tables. It does not
change `PUBLIC_DEMO_MODE` and does not require disabling read-only demo mode.

If the Neon database already contains a seed marker, the command exits without
inserting duplicates. To intentionally replace demo data, remove the simulated
rows and the corresponding `demo_seed_runs` marker manually, or use a new seed
key in code. Real records should not be removed.

---

## Testing

### Backend Tests

From the `backend` directory with the virtual environment active:

```powershell
python -m pytest tests -q
```

Run a specific test module:

```powershell
python -m pytest tests/test_detection.py -q
python -m pytest tests/test_reputation_api.py -q
python -m pytest tests/test_abuseipdb_client.py -q
```

The test suite covers traffic detection, alerts, configuration, database
persistence, IP validation, reputation caching, rate limiting, the reputation
API, the background worker, and the AbuseIPDB client. The tests use isolated
in-memory or temporary databases and do not require live AbuseIPDB requests.

`pytest` is the test runner. If it is not already available in your virtual
environment, install it before running the tests.

### Frontend Checks

From the `frontend` directory:

```powershell
npm run lint
npm run build
```

A separate frontend unit test runner is not configured in this project; linting
and the production build are the available frontend verification steps.

---

## Limitations

- **Local demonstration project.** SentinelX is intended for local educational
  and portfolio use. It is not hardened for production or untrusted networks.
- **IP reputation is disabled by default.** Enable it explicitly with
  `IP_REPUTATION_ENABLED=true`.
- **AbuseIPDB API key is required for provider lookups.** Without a key,
  reputation lookups return a sanitized `missing_key` provider error.
- **Detection, not prevention.** SentinelX identifies and reports suspicious
  activity; it does not block traffic, quarantine hosts, or modify firewall
  rules.
- **Windows-focused packet capture.** Interface discovery uses Windows-specific
  Scapy APIs. Live capture requires Npcap and typically Administrator
  privileges. Non-Windows deployments report capture as unsupported instead of
  failing requests.
- **Heuristic detection.** Port scan and traffic spike thresholds are simple
  rules and can produce false positives or miss slow or low-volume attacks.
- **No authentication or authorization.** The API is designed to run on a local
  machine. `PUBLIC_DEMO_MODE` provides read-only public demonstrations but is not
  a substitute for authentication. Do not expose write-capable instances to
  untrusted networks.
- **Database concurrency.** SQLite is the default local database and is not
  designed for high concurrency or multi-user deployments. PostgreSQL is
  supported, but SentinelX does not tune connection pool sizes or include a
  migration system.
- **Manual schema initialization.** Tables are created by `python -m app.init_db`.
  There is no automatic migration system; run the initializer after model
  changes.
- **Provider dependency.** AbuseIPDB lookups depend on network connectivity,
  provider availability, API quotas, and a valid key. Failures are surfaced as
  sanitized fallback responses.
- **Local plaintext data.** Captured traffic metadata and alerts are stored
  locally without encryption, and the local API uses HTTP rather than TLS.

---

## Repository

<https://github.com/prelobhp524-arch/SentinelX>
