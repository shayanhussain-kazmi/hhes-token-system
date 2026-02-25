from __future__ import annotations

import csv
import io
import os
from datetime import date, datetime
from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, Date, DateTime, Enum as SAEnum, ForeignKey, Integer, String, Text, create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./token_system.db")
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")
TOKEN_RESET_DAILY = os.getenv("TOKEN_RESET_DAILY", "true").lower() == "true"


class Base(DeclarativeBase):
    pass


class Role(str, Enum):
    ADMIN = "admin"
    STAFF = "staff"


class TokenStatus(str, Enum):
    WAITING = "waiting"
    CALLED = "called"
    COMPLETED = "completed"
    NO_SHOW = "no_show"
    CANCELLED = "cancelled"


class SmsType(str, Enum):
    CREATED = "created"
    CALLED = "called"
    REMINDER = "reminder"


class Department(Base):
    __tablename__ = "departments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    code: Mapped[str] = mapped_column(String(10), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    display_order: Mapped[int] = mapped_column(Integer, default=0)

    tokens: Mapped[list[Token]] = relationship(back_populates="department")


class DepartmentCounter(Base):
    __tablename__ = "department_counters"

    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"), primary_key=True)
    current_number: Mapped[int] = mapped_column(Integer, default=0)
    last_reset_date: Mapped[date] = mapped_column(Date, default=date.today)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[Role] = mapped_column(SAEnum(Role), default=Role.STAFF)
    department_id: Mapped[Optional[int]] = mapped_column(ForeignKey("departments.id"), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_number: Mapped[str] = mapped_column(String(20), unique=True)
    department_id: Mapped[int] = mapped_column(ForeignKey("departments.id"))
    visitor_name: Mapped[str] = mapped_column(String(100))
    phone: Mapped[str] = mapped_column(String(20))
    email: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    language: Mapped[str] = mapped_column(String(5), default="EN")
    status: Mapped[TokenStatus] = mapped_column(SAEnum(TokenStatus), default=TokenStatus.WAITING)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    called_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_source: Mapped[str] = mapped_column(String(20), default="tablet")
    called_by_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    department: Mapped[Department] = relationship(back_populates="tokens")


class SmsLog(Base):
    __tablename__ = "sms_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_id: Mapped[int] = mapped_column(ForeignKey("tokens.id"))
    phone: Mapped[str] = mapped_column(String(20))
    type: Mapped[SmsType] = mapped_column(SAEnum(SmsType))
    provider_message_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="sent")
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(50))
    token_id: Mapped[int] = mapped_column(ForeignKey("tokens.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)

app = FastAPI(title="HHES Token System")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "dev-secret"))
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


class CreateTokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(pattern=r"^\+[1-9]\d{7,14}$")
    email: Optional[EmailStr] = None
    department_id: int
    reason: Optional[str] = None
    language: str = "EN"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return f"plain::{password}"


def verify_password(password: str, stored: str) -> bool:
    return stored == hash_password(password)


def send_sms(db: Session, token: Token, sms_type: SmsType) -> None:
    db.add(SmsLog(token_id=token.id, phone=token.phone, type=sms_type, status="sent", provider_message_id="mocked"))


def require_user(request: Request, db: Session, roles: list[Role]) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = db.get(User, user_id)
    if not user or not user.is_active or user.role not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user


def next_token_number(db: Session, department: Department) -> str:
    counter = db.get(DepartmentCounter, department.id)
    today = date.today()
    if not counter:
        counter = DepartmentCounter(department_id=department.id, current_number=0, last_reset_date=today)
        db.add(counter)
    if TOKEN_RESET_DAILY and (not counter.last_reset_date or counter.last_reset_date != today):
        counter.current_number = 0
        counter.last_reset_date = today
    counter.current_number += 1
    return f"{department.code}-{counter.current_number:03d}"


def create_token(db: Session, payload: CreateTokenRequest) -> Token:
    department = db.get(Department, payload.department_id)
    if not department or not department.is_active:
        raise HTTPException(status_code=404, detail="Department not found")
    for _ in range(3):
        token = Token(
            token_number=next_token_number(db, department),
            department_id=department.id,
            visitor_name=payload.name,
            phone=payload.phone,
            email=payload.email,
            reason=payload.reason,
            language=payload.language,
            status=TokenStatus.WAITING,
        )
        db.add(token)
        try:
            db.commit()
            db.refresh(token)
            send_sms(db, token, SmsType.CREATED)
            db.commit()
            return token
        except IntegrityError:
            db.rollback()
    raise HTTPException(status_code=500, detail="Could not generate token")


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        if not db.scalar(select(func.count(Department.id))):
            departments = [
                Department(name="Accounts", code="ACC", display_order=1),
                Department(name="Administration", code="ADM", display_order=2),
                Department(name="Admissions", code="ADS", display_order=3),
                Department(name="Principal", code="PRI", display_order=4),
            ]
            db.add_all(departments)
            db.flush()
            for dep in departments:
                db.add(DepartmentCounter(department_id=dep.id, current_number=0, last_reset_date=date.today()))
        if not db.scalar(select(func.count(User.id)).where(User.role == Role.ADMIN)):
            db.add(User(username="admin", password_hash=hash_password(DEFAULT_ADMIN_PASSWORD), role=Role.ADMIN))
        db.commit()


@app.get("/", response_class=RedirectResponse)
def root() -> str:
    return "/checkin"


@app.get("/checkin", response_class=HTMLResponse)
def checkin_page(request: Request, db: Session = Depends(get_db)):
    departments = db.scalars(select(Department).where(Department.is_active.is_(True)).order_by(Department.display_order)).all()
    return templates.TemplateResponse(request, "checkin.html", {"departments": departments})


@app.post("/checkin", response_class=HTMLResponse)
def checkin_submit(
    request: Request,
    name: str = Form(...),
    phone: str = Form(...),
    email: Optional[str] = Form(None),
    department_id: int = Form(...),
    reason: Optional[str] = Form(None),
    language: str = Form("EN"),
    db: Session = Depends(get_db),
):
    token = create_token(db, CreateTokenRequest(name=name, phone=phone, email=email, department_id=department_id, reason=reason, language=language))
    return templates.TemplateResponse(request, "checkin_success.html", {"token": token, "department": token.department})


@app.post("/api/tokens")
def create_token_api(payload: CreateTokenRequest, db: Session = Depends(get_db)):
    token = create_token(db, payload)
    waiting_before = db.scalar(
        select(func.count(Token.id)).where(Token.department_id == token.department_id, Token.status == TokenStatus.WAITING, Token.created_at < token.created_at)
    )
    return {
        "token_number": token.token_number,
        "department_name": token.department.name,
        "position_estimate": waiting_before,
    }


@app.get("/display", response_class=HTMLResponse)
def display_page(request: Request):
    return templates.TemplateResponse(request, "display.html", {})


@app.get("/api/display")
def display_api(db: Session = Depends(get_db)):
    departments = db.scalars(select(Department).order_by(Department.display_order)).all()
    now_serving = []
    for dep in departments:
        current = db.scalar(select(Token).where(Token.department_id == dep.id, Token.status == TokenStatus.CALLED).order_by(Token.called_at.desc()))
        if current:
            now_serving.append({"id": current.id, "department": dep.name, "token_number": current.token_number})
    recent = db.scalars(select(Token).where(Token.status.in_([TokenStatus.COMPLETED, TokenStatus.NO_SHOW])).order_by(Token.completed_at.desc(), Token.called_at.desc()).limit(10)).all()
    waiting_counts = [
        {"department": dep.name, "count": db.scalar(select(func.count(Token.id)).where(Token.department_id == dep.id, Token.status == TokenStatus.WAITING))}
        for dep in departments
    ]
    return {
        "nowServing": now_serving,
        "recentCompleted": [{"token_number": t.token_number, "department": t.department.name, "status": t.status.value} for t in recent],
        "waitingCounts": waiting_counts,
    }


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session["user_id"] = user.id
    if user.role == Role.ADMIN:
        return RedirectResponse("/admin", status_code=303)
    return RedirectResponse("/staff", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/staff", response_class=HTMLResponse)
def staff_page(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db, [Role.STAFF, Role.ADMIN])
    department_filter = user.department_id
    if user.role == Role.ADMIN and request.query_params.get("department_id"):
        department_filter = int(request.query_params["department_id"])
    waiting = db.scalars(
        select(Token).where(Token.department_id == department_filter, Token.status == TokenStatus.WAITING).order_by(Token.created_at)
    ).all() if department_filter else []
    current = db.scalar(select(Token).where(Token.department_id == department_filter, Token.status == TokenStatus.CALLED).order_by(Token.called_at.desc())) if department_filter else None
    departments = db.scalars(select(Department).order_by(Department.display_order)).all()
    return templates.TemplateResponse(request, "staff.html", {"user": user, "waiting": waiting, "current": current, "departments": departments, "department_filter": department_filter})


def _get_department_for_user(user: User, department_id: Optional[int]) -> int:
    if user.role == Role.ADMIN:
        if not department_id:
            raise HTTPException(status_code=400, detail="department_id required for admin")
        return department_id
    if not user.department_id:
        raise HTTPException(status_code=400, detail="Staff user missing department assignment")
    return user.department_id


@app.post("/api/departments/{department_id}/call-next")
def call_next(department_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db, [Role.STAFF, Role.ADMIN])
    target_dep = _get_department_for_user(user, department_id)
    token = db.scalar(select(Token).where(Token.department_id == target_dep, Token.status == TokenStatus.WAITING).order_by(Token.created_at).limit(1))
    if not token:
        return JSONResponse({"message": "No waiting tokens"}, status_code=404)
    token.status = TokenStatus.CALLED
    token.called_at = datetime.utcnow()
    token.called_by_user_id = user.id
    send_sms(db, token, SmsType.CALLED)
    db.add(AuditLog(user_id=user.id, action="CALL_TOKEN", token_id=token.id))
    db.commit()
    return {"token_id": token.id, "token_number": token.token_number, "department": token.department.name}


@app.post("/api/tokens/{token_id}/complete")
def complete_token(token_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db, [Role.STAFF, Role.ADMIN])
    token = db.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    if user.role == Role.STAFF and token.department_id != user.department_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    token.status = TokenStatus.COMPLETED
    token.completed_at = datetime.utcnow()
    db.add(AuditLog(user_id=user.id, action="COMPLETE_TOKEN", token_id=token.id))
    db.commit()
    return {"status": token.status.value}


@app.post("/api/tokens/{token_id}/no-show")
def no_show_token(token_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db, [Role.STAFF, Role.ADMIN])
    token = db.get(Token, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    if user.role == Role.STAFF and token.department_id != user.department_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    token.status = TokenStatus.NO_SHOW
    db.add(AuditLog(user_id=user.id, action="NO_SHOW_TOKEN", token_id=token.id))
    db.commit()
    return {"status": token.status.value}


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db, [Role.ADMIN])
    departments = db.scalars(select(Department).order_by(Department.display_order)).all()
    users = db.scalars(select(User).order_by(User.id)).all()
    return templates.TemplateResponse(request, "admin.html", {"departments": departments, "users": users})


@app.post("/admin/departments")
def create_department(request: Request, name: str = Form(...), code: str = Form(...), db: Session = Depends(get_db)):
    require_user(request, db, [Role.ADMIN])
    dep = Department(name=name, code=code.upper(), is_active=True, display_order=99)
    db.add(dep)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.get("/api/reports/summary")
def report_summary(request: Request, from_date: date = Query(..., alias="from"), to_date: date = Query(..., alias="to"), db: Session = Depends(get_db)):
    require_user(request, db, [Role.ADMIN])
    rows = db.scalars(select(Token).where(Token.created_at >= datetime.combine(from_date, datetime.min.time()), Token.created_at <= datetime.combine(to_date, datetime.max.time()))).all()
    visitors = len(rows)
    wait_times = [(t.called_at - t.created_at).total_seconds() for t in rows if t.called_at]
    service_times = [(t.completed_at - t.called_at).total_seconds() for t in rows if t.called_at and t.completed_at]
    return {
        "visitors": visitors,
        "avg_wait_seconds": sum(wait_times) / len(wait_times) if wait_times else 0,
        "avg_service_seconds": sum(service_times) / len(service_times) if service_times else 0,
    }


@app.get("/api/reports/department")
def report_department(request: Request, dept_id: int, from_date: date = Query(..., alias="from"), to_date: date = Query(..., alias="to"), db: Session = Depends(get_db)):
    require_user(request, db, [Role.ADMIN])
    rows = db.scalars(select(Token).where(Token.department_id == dept_id, Token.created_at >= datetime.combine(from_date, datetime.min.time()), Token.created_at <= datetime.combine(to_date, datetime.max.time()))).all()
    wait_times = [(t.called_at - t.created_at).total_seconds() for t in rows if t.called_at]
    service_times = [(t.completed_at - t.called_at).total_seconds() for t in rows if t.called_at and t.completed_at]
    return {
        "department_id": dept_id,
        "visitors": len(rows),
        "avg_wait_seconds": sum(wait_times) / len(wait_times) if wait_times else 0,
        "avg_service_seconds": sum(service_times) / len(service_times) if service_times else 0,
    }


@app.get("/api/export/tokens.csv")
def export_tokens(request: Request, from_date: date = Query(..., alias="from"), to_date: date = Query(..., alias="to"), db: Session = Depends(get_db)):
    require_user(request, db, [Role.ADMIN])
    rows = db.scalars(select(Token).where(Token.created_at >= datetime.combine(from_date, datetime.min.time()), Token.created_at <= datetime.combine(to_date, datetime.max.time())).order_by(Token.created_at)).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["token_number", "department", "status", "created_at", "called_at", "completed_at"])
    for t in rows:
        writer.writerow([t.token_number, t.department.name, t.status.value, t.created_at, t.called_at, t.completed_at])
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=tokens.csv"})


@app.get("/health")
def health() -> PlainTextResponse:
    return PlainTextResponse("ok")
