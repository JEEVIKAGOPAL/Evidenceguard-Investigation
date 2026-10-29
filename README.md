# EvidenceGuard — Wazuh Investigation Evidence Gap Prototype

A small FastAPI application for reviewing security alerts, checking investigation evidence, generating analyst guidance, and exporting JSON reports.

## Included features

- Login-protected API and dashboard (prototype authentication).
- SQLite storage for incidents and audit events.
- Evidence statuses: `available`, `missing`, `unchecked`, `unavailable`.
- Rule-based evidence gap analysis and transparent fallback recommendations.
- Optional Wazuh Manager API integration for agent inventory.
- Optional ingestion from an accessible `alerts.json` file.
- Demo alerts clearly labelled as illustrative sample data.
- JSON report download.

## 1. Install and run (Windows / VS Code)

1. Extract the ZIP to a folder.
2. Open the `evidenceguard` folder in VS Code.
3. Open Terminal and create a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and change `ADMIN_PASSWORD`.
5. For the first UI test, leave `DEMO_MODE=true`. Do not enter real Wazuh credentials until you are ready to configure the integration.
6. Start the app:

   ```powershell
   uvicorn main:app --reload
   ```

7. Open `http://127.0.0.1:8000` or `http://127.0.0.1:8000/docs`.
8. Sign in using the username/password in `.env`.

Default prototype login when using the unchanged example file: `admin` / `ChangeThisPassword123!`. Change it before using this on a network.

## 2. Wazuh integration

Set `WAZUH_API_URL`, `WAZUH_USERNAME`, and `WAZUH_PASSWORD` in `.env`. The manager API is commonly available on port `55000`, but use the URL configured in your lab. Test that the computer running FastAPI can reach that host and port. For production, use trusted TLS certificates and set `WAZUH_VERIFY_SSL=true`.

`GET /api/wazuh/agents` calls the Wazuh Manager API. It returns an explicit HTTP error if the connection fails; it does not pretend sample data is live.

For alerts, set `WAZUH_ALERTS_FILE` to a path that the FastAPI process can read. The file must contain JSON objects one per line, as Wazuh's `alerts.json` normally does. If FastAPI runs on Windows and Wazuh runs on a separate Ubuntu VM, the Windows process cannot read a Linux path directly; use a secure, authorized shared path or copy test logs to a local file. If not configured and `DEMO_MODE=true`, the alerts endpoint returns labelled sample alerts.

## 3. Core workflow

1. Sign in.
2. Review the dashboard and incidents.
3. Open an incident and review its alert fields.
4. Set each evidence item to Available, Missing, Unchecked, or Unavailable based on what was actually checked.
5. Run evidence analysis.
6. Review recommendations and limitations.
7. Download the JSON report.

## Important limitations

- This is a local learning prototype, not a production SOC platform.
- The included recommendation engine is explicitly labelled `rule_based_fallback`; it does not claim that an LLM was called. A provider can be integrated later in `llm_service.py`.
- Do not expose this prototype to the internet. Its in-memory access tokens do not have production-grade expiration/revocation infrastructure.
- The application never runs commands or automatically blocks IPs. Analyst review is required.
- Sample alerts are illustrative and must not be presented as real security telemetry.
