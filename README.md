# Trinetra AI

Trinetra AI is a modular, local-first cybersecurity indicator investigation tool. It supports domain, IP address, and HTTP(S) URL analysis; validates and extracts IOC candidates from text; records investigation reports; and can request optional reputation lookups.

## Run on Windows

From PowerShell in the project folder:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe run.py
```

Open `http://127.0.0.1:5000`. The Flask development server runs with debugging disabled. Do not expose it directly to the public internet; authentication and production server deployment are not currently included.

The project has an existing local `.env` file. Keep that file private. `.env` is ignored and removed from Git tracking; `.env.example` contains placeholder settings only. If configuring a new environment, copy `.env.example` to `.env` and replace `SECRET_KEY` with a random value.

## Configuration

All settings are optional except a strong secret key for a persistent deployment. The SQLite database remains the default.

```dotenv
SECRET_KEY=replace-with-a-long-random-value
DATABASE_URL=sqlite:///trinetra.db
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SESSION_COOKIE_SECURE=false
```

- `SECRET_KEY`: Flask session and CSRF signing secret. The app generates a temporary random key if it is absent; sessions then do not survive process restarts.
- `DATABASE_URL`: SQLAlchemy database URL. The default remains the existing `instance/trinetra.db` database.
- `VIRUSTOTAL_API_KEY`: optional VirusTotal v3 API key.
- `ABUSEIPDB_API_KEY`: optional AbuseIPDB API key.
- `SESSION_COOKIE_SECURE`: set to `true` behind HTTPS; keep `false` for local HTTP development.

Enrichment is opt-in per investigation. A selected lookup sends the normalized indicator to configured providers. No API keys are required for the local workflow. Provider failures, missing keys, timeouts, and rate limits are reported as statuses and do not invent reputation results.

## Investigation workflow

1. The request is classified and validated as a domain, IP, or URL.
2. A deterministic analyzer normalizes the indicator and records local observations and separate heuristic signals.
3. Optional VirusTotal and AbuseIPDB adapters run only when selected on the form. They use fixed provider endpoints, bounded timeouts, and no redirects; the target URL itself is never fetched.
4. The risk engine assigns a 0–100 review-priority score from explicit heuristics and provider findings. Zero is `Unassessed`; increasing score bands are `Low`, `Suspicious`, `High Risk`, and `Critical`. These labels are review priorities, not a probability or proof of compromise. The app does not treat domain keywords or TLD choice as malicious evidence.
5. The completed summary, evidence, recommendations, provider details, and source limitations are stored with the investigation.

The IOC extractor validates and deduplicates IPv4 addresses, domains, URLs, email addresses, MD5, SHA-1, and SHA-256 hashes locally. It does not store pasted text or perform threat verification.

## Database compatibility

On startup, the application creates missing tables and adds optional report columns to the existing `investigations` table. This is an additive SQLite migration: it preserves `target`, all existing records, IDs, timestamps, and the original verdicts. Existing rows are marked `legacy` because their earlier evidence was not stored. Back up `instance/trinetra.db` before deploying application changes. No database reset is needed.

## Tests

Run the built-in test suite from PowerShell:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use an isolated in-memory SQLite database and do not modify the saved investigation history.

## Current limitations

- The tool does not perform DNS lookups, HTTP fetches, TLS checks, active scans, or automatic URL following.
- Reputation lookups depend on provider credentials, coverage, quotas, and correctness. A missing record or low score does not establish safety.
- No authentication, multi-user separation, background job queue, or production deployment configuration is included.
- Hash IOCs can be extracted but are not yet accepted as investigation targets.
- Detailed evidence cannot be reconstructed for legacy reports; their saved target, score, verdict, and timestamp remain available.
