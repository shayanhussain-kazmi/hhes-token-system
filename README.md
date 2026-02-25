# HHES Smart Token System

FastAPI-based queue/token system with public check-in, live display, staff console, admin panel, SMS logging, and reporting APIs.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- `/checkin` tablet intake
- `/display` TV monitor
- `/login` staff/admin login

Default admin credentials:
- `admin / admin123`

## Core features implemented

- Public token creation with E.164 validation and department-based numbering.
- SMS event logging for token created/called.
- Staff queue actions: call-next, complete, no-show.
- Display API + page with auto-refresh polling.
- Admin department management and summary/department/csv reports.
- Audit logs for queue actions.
