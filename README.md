# Trinetra AI

Trinetra AI is a local-first cybersecurity indicator investigation tool. It analyzes domains, IP addresses, and HTTP(S) URLs; extracts validated IOCs from text; records explainable investigation reports; and can request optional VirusTotal and AbuseIPDB reputation lookups.

## Local development

Use the existing virtual environment. Do not install packages as part of routine setup:

These commands are for a **new, empty database**. If you have an existing database with investigations, follow the backup-first sequence in [Existing database and legacy records](#existing-database-and-legacy-records) instead.

```powershell
$env:TRINETRA_ENV = "development"
$env:SECRET_KEY = (.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
.\venv\Scripts\flask.exe --app run.py provision-admin admin
.\venv\Scripts\flask.exe --app run.py db-backup --output instance\backups\initial.sqlite
.\venv\Scripts\flask.exe --app run.py db-upgrade --backup instance\backups\initial.sqlite
.\venv\Scripts\python.exe run.py
```

Open `http://127.0.0.1:5000`. The development server binds to loopback with debugging disabled. Do not expose it directly to the public internet. For repeatable local sessions, keep the generated `SECRET_KEY` private and stable in the untracked `.env` file instead of generating a new value on each shell start. `.env.example` contains placeholders only.

`provision-admin` is available only while there are no accounts. It prompts for a password without echoing it. The application has no public registration endpoint. Administrators create accounts from **Users**; the initial password is displayed once, must be delivered using a separate secure channel, and must be changed at first sign-in.

## Accounts and authorization

The supported roles are **Administrator** and **Standard user**. Administrators can create accounts, issue temporary passwords, activate or deactivate accounts, and review account-management audit events. Standard users can use the investigation workflow. Administrators do not gain access to other users' investigations through their role.

Investigation history, dashboard totals, report pages, report downloads, and activity logs are filtered by the authenticated owner in server-side queries. Requests for another account's report return 404. Investigation activity is linked to its owner at the database level. Password changes and account deactivation revoke existing sessions. Login errors are generic and login attempts are throttled by username/IP pair and by IP.

Passwords are stored with Werkzeug's scrypt password hashing. Browser state-changing requests require CSRF tokens. Session cookies are HttpOnly and SameSite=Lax; production requires Secure cookies and a persistent secret key. Sessions expire after eight hours. This first version does not include MFA, email-based account recovery, or self-service registration.

## Existing database and legacy records

**Do not point migration tests at the working database.** The ownership migration is explicit, versioned, SQLite-only, and never runs on application startup. The existing database must be backed up before any account provisioning or schema migration. Migration version 2 assigns all pre-authentication investigations and their associated activity rows only to an explicitly provisioned, active **Standard user** marked as the legacy owner. It does not assign them to the administrator. The legacy owner must change the initial password at first sign-in. Administrators still cannot view that user's reports.

Before migrating an existing database, stop the app and follow this sequence from PowerShell. Use a durable random secret in `.env` and set `TRINETRA_ENV=development` for local HTTP:

```powershell
# Capture the untouched database before provisioning changes its schema.
.\venv\Scripts\flask.exe --app run.py db-backup --output instance\backups\before-auth.sqlite

# Create the first administrator; enter a strong password at the hidden prompt.
.\venv\Scripts\flask.exe --app run.py provision-admin admin

# Create a restricted standard account explicitly designated for old records.
.\venv\Scripts\flask.exe --app run.py provision-legacy-owner legacy-analyst

# Back up the provisioned state, then verify it immediately before migration.
.\venv\Scripts\flask.exe --app run.py db-backup --output instance\backups\before-ownership.sqlite
.\venv\Scripts\flask.exe --app run.py db-upgrade --backup instance\backups\before-ownership.sqlite --legacy-owner legacy-analyst
```

The commands refuse to overwrite backup or restore files. Backup checks include SQLite integrity, schema, row counts, and a private logical-data digest. Keep backups in access-controlled storage and retain them according to your organization's data-retention policy. The pre-authentication backup is an emergency recovery point; it does not include the newly provisioned user accounts. The second backup is the migration rollback point.

To validate recovery, restore to a **new, separate path**, then inspect that copy without replacing the active database:

```powershell
.\venv\Scripts\flask.exe --app run.py db-restore-copy --backup instance\backups\before-ownership.sqlite --destination instance\backups\restore-check.sqlite
```

A restore copy is never automatically made active. If migration fails, leave the source database in place, preserve both backups, inspect the safe error, and restore to another new path for investigation. Do not delete or replace the working database as a recovery shortcut. The migration currently supports SQLite only; it stops if the legacy schema differs from the expected version, custom indexes/triggers exist, or orphaned activity rows are detected.

For a new empty database, provision the administrator first, then make a backup and run `db-upgrade` without `--legacy-owner`. The same explicit upgrade establishes schema version 2.

## Configuration and deployment

Copy `.env.example` to `.env`, set a persistent random `SECRET_KEY` of at least 32 bytes, and choose `TRINETRA_ENV=development` for local HTTP or `TRINETRA_ENV=production` behind HTTPS. Production startup rejects a missing, weak, or known placeholder secret and refuses insecure cookies. It never generates a production secret. Set `SESSION_COOKIE_SECURE=true` in production. `TRUSTED_PROXY_COUNT` defaults to zero; set it only to the exact number of trusted reverse proxies that set forwarded client IP and scheme headers. Never trust forwarded headers from arbitrary clients.

Use a production WSGI server and HTTPS-terminating reverse proxy for shared deployment. Configure TLS, request limits, backups, monitoring, access-controlled logs, and database file permissions. Do not expose Flask's development server. No shared-deployment environment or external production deployment has been verified as part of this implementation.

```dotenv
TRINETRA_ENV=development
SECRET_KEY=replace-with-a-long-random-value
DATABASE_URL=sqlite:///trinetra.db
SESSION_COOKIE_SECURE=false
TRUSTED_PROXY_COUNT=0
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

Enrichment is opt-in per investigation. A selected provider lookup sends the normalized indicator to the configured provider. Fixed provider endpoints, bounded timeouts, and disabled redirects are used; the target URL itself is not fetched. Provider errors and missing coverage do not invent reputation results. IOC extraction is local and does not save pasted text. Investigation targets and reports are retained in the local database; keep database files and backups private and apply a retention policy.

## Analysis and limitations

The analyzer validates and normalizes indicators and records local observations separately from heuristics and provider evidence. A 0–100 score is a review-priority score, not probability or proof of compromise. Missing scored evidence yields an Unassessed result. The IOC extractor validates and deduplicates IPv4 addresses, domains, URLs, email addresses, and MD5/SHA-1/SHA-256 hashes; hash investigations, DNS/HTTP/TLS checks, active scans, background jobs, MFA, email reset, and production deployment are not included.

## Tests

Run the complete suite with the existing environment:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use isolated temporary or in-memory databases and mock external providers. The ownership migration is exercised against a disposable synthetic database. The live local investigation database is not migrated by the test suite.
