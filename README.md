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
- Department token counters reset automatically each day when the first token is created for that department (no cron job required).
- Display screen announces newly called tokens with a short chime + browser speech synthesis; voice selection depends on English voices installed on the device/browser, and some TVs may need one user interaction to enable audio autoplay.
- Admin department management and summary/department/csv reports.
- Audit logs for queue actions.

## SMS note

SMS notifications are currently **logging only** via `sms_logs` (no real provider is called yet).
To enable real sending later, integrate an SMS provider such as Twilio or a UAE SMS gateway inside `send_sms` in `app/main.py` and store provider credentials in environment variables.
