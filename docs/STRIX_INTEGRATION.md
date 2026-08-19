# IntelliSec + Strix AI Security Engine Integration

## Overview

IntelliSec integrates the open-source Strix autonomous AI penetration-testing framework as a modular security engine. This enables IntelliSec to perform AI-powered vulnerability assessments alongside its existing deterministic HTTP/TLS scanning capabilities.

## Architecture

```
IntelliSec Frontend (React)
        ↓
IntelliSec Backend API (FastAPI)
  ├── POST /api/scans           → Existing deterministic scan (synchronous)
  ├── POST /api/scans/security  → New AI security scan (async background task)
  ├── GET  /api/scans/:id/status → Scan progress polling
  └── GET  /api/scans/:id/report → Executive report
        ↓
StrixService (backend/app/strix_engine/)
  ├── Builds scan configuration
  ├── Launches Strix as subprocess
  ├── Monitors scan progress
  └── Parses results into IntelliSec format
        ↓
Strix Core (run_strix_scan)
  ├── AI Agent orchestration
  ├── Docker sandbox execution
  ├── Reconnaissance & exploitation
  └── Report generation
        ↓
Results → IntelliSec Database → Dashboard
```

## Prerequisites

### Required
- **Python 3.12+** — Strix requires Python 3.12 or newer
- **Docker Desktop** — Strix executes scans inside Docker containers
- **LLM API Key** — An API key for an LLM provider (OpenAI, Anthropic, Google, etc.)
- **Node.js 18+** — For the IntelliSec frontend

### Strix Source
The Strix source code should be extracted and available at a path specified by `STRIX_PATH`.

## Environment Variables

Add these to your `.env` file:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STRIX_LLM` | Yes | — | LLM model name (e.g., `gpt-4o`, `claude-sonnet-4-20250514`, `gemini/gemini-2.5-pro`) |
| `LLM_API_KEY` | Yes | — | API key for the LLM provider |
| `STRIX_DOCKER_IMAGE` | No | `ghcr.io/strix-labs/strix-sandbox:latest` | Docker image for the scan sandbox |
| `STRIX_MAX_TURNS` | No | `100` | Maximum LLM turns per scan |
| `STRIX_SCAN_TIMEOUT` | No | `1800` | Maximum scan duration in seconds |
| `STRIX_PATH` | Yes | — | Path to the extracted Strix source directory |

**Never commit real API keys.** Use `.env` files that are in `.gitignore`.

## How to Start IntelliSec

### Backend
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Strix Setup
```bash
# Extract Strix source
# Set STRIX_PATH in .env to point to the extracted directory
# Install Strix dependencies in its own venv:
cd <strix-path>
python -m venv .venv
.venv\Scripts\activate
pip install -e .

# Pull the Docker sandbox image:
docker pull ghcr.io/strix-labs/strix-sandbox:latest
```

## How to Start a Security Scan

1. Log into IntelliSec
2. Navigate to "New Scan"
3. Select the "AI Security Scan" tab
4. Enter a scan name and target URL
5. Select target type and scan mode
6. Confirm authorization
7. Click "Start Security Scan"
8. Monitor progress on the scan progress page
9. View results once the scan completes

## How Scans Work

1. **Frontend** sends `POST /api/scans/security` with target details
2. **Backend** validates the target, creates a scan record, returns scan ID
3. **Background task** launches Strix as a subprocess
4. **Strix** spins up a Docker sandbox, runs AI agents for recon/exploitation
5. **Strix** writes results to `strix_runs/<scan-id>/`:
   - `run.json` — scan metadata and status
   - `vulnerabilities.json` — list of found vulnerabilities
   - `report.md` — executive summary
   - `findings.sarif` — SARIF format for CI/CD
6. **Backend** reads and parses the output files
7. **Backend** normalizes findings into IntelliSec format
8. **Backend** computes security score and updates the database
9. **Frontend** displays results on the dashboard

## Where Results Are Stored

- **Database**: Findings are stored in the main IntelliSec database (MongoDB or JSON file)
- **Strix artifacts**: Raw Strix output is in `backend/strix_runs/<scan-id>/`
- **Reports**: Executive reports in Markdown, SARIF in JSON

## How Findings Are Parsed

The parser (`backend/app/strix_engine/parser.py`) converts Strix vulnerability reports into IntelliSec findings:

| Strix Field | IntelliSec Field |
|------------|------------------|
| `title` | `title` |
| `severity` | `severity` |
| `description` | `description` |
| `evidence` | `evidence` |
| `remediation_steps` | `remediation` |
| `cvss` | `cvss`, `base_score` |
| `endpoint` | `affected_component` |
| `finding_class` | `finding_type` |
| `impact` | `impact` |
| `technical_analysis` | `technical_analysis` |
| `cve` | `cve` |
| `cwe` | `cwe` |

## Troubleshooting

### "Strix is not ready" error
- Check that `STRIX_LLM` and `LLM_API_KEY` are set in `.env`
- Check that Docker Desktop is running
- Check that `STRIX_PATH` points to the correct directory
- Run the preflight check: `GET /api/scans/security/preflight`

### Scan stuck in "queued" or "running"
- Check backend logs for errors
- Verify Docker can pull the sandbox image
- Check LLM API key validity
- Check `STRIX_SCAN_TIMEOUT` (default: 30 minutes)

### No findings after scan completes
- Check `strix_runs/<scan-id>/vulnerabilities.json`
- Check `strix_runs/<scan-id>/run.json` for the scan status
- Some targets may genuinely have no vulnerabilities

### Docker issues
- Ensure Docker Desktop is running
- Try `docker pull ghcr.io/strix-labs/strix-sandbox:latest` manually
- Check Docker has enough resources allocated (recommended: 4GB+ RAM)

## Safety & Ethics

- Only scan targets you own or have explicit authorization to test
- All scans require user confirmation of authorization
- Scans run inside Docker sandboxes for isolation
- No destructive exploitation is performed
- Private/local/metadata targets are blocked
- API keys are never exposed in frontend code or logs
