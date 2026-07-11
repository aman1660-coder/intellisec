# IntelliSec

**Research title:** IntelliSec: Towards Intelligent Web Security Posture Management Through Cryptographic Risk Analysis, Attack-Path Correlation, Compliance Mapping, and Post-Quantum Readiness Assessment

IntelliSec is a production-style implementation of the research paper as a deployable web security posture intelligence platform. It accepts an authorized web target, performs deterministic TLS, certificate, HTTP header, and cookie checks, then transforms structured findings into attack paths, contextual risk scores, compliance mappings, PQC readiness, and audience-specific reports.

## Research Gap

Free scanners can detect web misconfigurations, but they rarely connect findings into attacker logic, compliance controls, business context, and quantum migration readiness. IntelliSec implements that missing intelligence layer while keeping LLMs out of the detection path.

## Six Pillars

- TLS and cryptographic configuration analysis
- Deterministic web security checks with structured evidence
- Directed attack-path correlation with chain amplification
- Five-factor contextual risk scoring
- Technical-to-compliance mapping for GDPR, NIST, and PCI-DSS
- Post-quantum cryptography readiness assessment

## Architecture

```text
frontend/ React + Vite + Tailwind + Recharts
backend/  FastAPI + deterministic scanners + research engines
docs/     deployment notes
sample-data/ labeled case-study metadata
```

Processing flow:

```text
Authorized URL
-> SSRF-safe validation
-> deterministic TLS/certificate/header/cookie checks
-> structured findings
-> NetworkX attack-path correlation
-> five-factor risk scoring
-> compliance mapping
-> PQC readiness
-> AI interpretation or deterministic fallback
-> developer, compliance, and executive reports
```

## Core Research Mechanics

### Attack-Path Formula

The backend implements the paper's equation:

```text
alpha(k) = 1 + 0.35 * ln(k), k >= 2
Scomposite = mean_base_score * alpha(k)
```

The paper's printed example reports mean `3.83`, `alpha(3)=1.38`, and composite `9.1/10`. Mathematically, `3.83 * 1.38 = 5.3`, not `9.1`. IntelliSec preserves the published methodology by implementing the equation exactly and documents this discrepancy transparently in code and tests.

### Five-Factor Risk

Each dimension is scored from 0 to 2:

- D1 Exploitability
- D2 Data Sensitivity
- D3 Cryptographic Weakness Depth
- D4 Exposure Surface
- D5 Chain Amplification

The sum is normalized to a 0-10 contextual risk score.

### PQC Readiness

The PQC engine scores:

- key exchange and cryptographic dependency
- TLS 1.3 adoption status
- certificate signature algorithm
- quantum risk window against the NIST 2035 migration target

TLS 1.3 is treated as a migration prerequisite, not as proof of PQC usage.

## Ethical Use

IntelliSec is for owned or explicitly authorized targets only. It does not exploit vulnerabilities, brute force credentials, exfiltrate data, evade detection, persist, or perform denial-of-service behavior. The backend blocks localhost, loopback, private IPs, link-local IPs, metadata endpoints, unsupported protocols, embedded credentials, and unsafe redirects.

## Local Setup

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
uvicorn main:app --reload --port 8000
```

Health check:

```bash
curl http://localhost:8000/api/health
```

### Frontend

```bash
cd frontend
npm install
copy .env.example .env
npm run dev
```

Open `http://localhost:5173`.

## Environment Variables

```text
MONGODB_URI=
MONGODB_DB=intellisec
JWT_SECRET=
AI_PROVIDER=gemini
AI_API_KEY=
AI_MODEL=gemini-1.5-flash
FRONTEND_URL=http://localhost:5173
CORS_ORIGINS=http://localhost:5173
SCAN_TIMEOUT=6
MAX_REDIRECTS=3
MAX_RESPONSE_BYTES=262144
RATE_LIMIT=20
VITE_API_URL=http://localhost:8000/api
```

The app works without `AI_API_KEY`; it uses deterministic fallback summaries.

## API Overview

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/targets/validate`
- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/attack-paths`
- `GET /api/scans/{scan_id}/compliance`
- `GET /api/scans/{scan_id}/pqc`
- `GET /api/scans/{scan_id}/reports`
- `GET /api/case-study`
- `GET /api/health`

## Research Case Study Mode

`/api/case-study` and the frontend case-study page generate a labeled **Research Paper Case Study Dataset**. It is not a live scan. It demonstrates eight deterministic findings, two paper-aligned attack chains, compliance mapping, PQC readiness, AI fallback, and all three report modes.

## Testing

```bash
cd backend
pytest
```

Tests cover SSRF protection, deterministic header/cookie findings, graph construction, chain amplification, risk scoring, compliance mapping, PQC scoring, and case-study completeness.

Frontend build:

```bash
cd frontend
npm run build
```

## Deployment

- Frontend: Vercel, with `frontend` as the root and `VITE_API_URL` pointing to the Render backend.
- Backend: Render Docker service using `backend/Dockerfile` or `render.yaml`.
- Database: MongoDB Atlas via `MONGODB_URI`; local JSON storage is only a demo fallback.

See `docs/deployment.md`.

## Limitations

- Correlation rules are hand-crafted from documented attack patterns.
- PQC scoring uses a configurable but static 2035 regulatory timeline.
- Role-stratified LLM output evaluation remains future work.
- Automated compliance mappings are technical indicators, not legal certification.
- Live TLS probing can be limited by host, CDN, runtime OpenSSL, or network policy; unavailable checks are reported transparently.

## Future Work

- Learn correlation edges from incident and breach data.
- Add scheduled monitoring and notification integrations.
- Expand certificate-chain metadata where runtime TLS APIs expose it.
- Add formally evaluated role-specific AI report scoring.
- Support PDF export after printable and JSON report workflows.

## Authors

Research paper authors: Aman Kumar Singh, Rohith Krishna S, Harrshan S, Neraniki Dinesh Kumar, Ms. Inchara K P, and Dr. Madhumala R B.

## License

Add a license file appropriate for the academic or portfolio release model before publishing.
