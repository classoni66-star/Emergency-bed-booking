"""
JK Pancrass Emergency Bed System — Single-file MVP
==================================================
Free-to-patient, feature-phone-first emergency bed booking for
JK Pancrass Medical Clinic, Mayuge, Uganda.

SETUP
-----
1) pip install -r requirements.txt   (or: pip install fastapi "uvicorn[standard]" sqlalchemy passlib[bcrypt] "python-jose[cryptography]" httpx python-multipart pydantic-settings)
2) export SECRET_KEY="a-long-random-string"
3) uvicorn main:app --reload --port 8000
4) open http://localhost:8000

DEMO LOGINS (created automatically on first run)
------------------------------------------------
Admin:  +256700000001 / admin123
Staff:  +256700000002 / staff123

AFRICA'S TALKING (go live)
--------------------------
- Set env vars: AT_USERNAME, AT_API_KEY, AT_SENDER_ID
- Point SMS callback  -> POST https://your-domain/api/webhooks/sms
- Point USSD callback -> POST https://your-domain/api/webhooks/ussd
- Request a SHARED, POSTPAID USSD shortcode from AT (toll-free for patients).
- Request REVERSE BILLING on the SMS shortcode (free for patients).
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import (
    Depends, FastAPI, Header, HTTPException, Request, status,
)
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker,
)
from fastapi.responses import RedirectResponse

# ============================================================================
# CONFIG
# ============================================================================
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MIN = 60 * 24
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./bedbook.db")

AT_USERNAME = os.environ.get("AT_USERNAME", "sandbox")
AT_API_KEY = os.environ.get("AT_API_KEY", "")
AT_SENDER_ID = os.environ.get("AT_SENDER_ID", "")
INGEST_KEY = os.environ.get("INGEST_KEY", "")
CLINIC_NAME = os.environ.get("CLINIC_NAME", "JK Pancrass Medical Clinic")

# ============================================================================
# DATABASE
# ============================================================================
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# MODELS
# ============================================================================
class StaffUser(Base):
    __tablename__ = "staff_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    phone: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="staff")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BedRequest(Base):
    __tablename__ = "bed_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    patient_phone: Mapped[str] = mapped_column(String(32), index=True)
    patient_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    channel: Mapped[str] = mapped_column(String(16), default="sms")
    status: Mapped[str] = mapped_column(String(24), default="pending")
    claimed_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    claimed_by: Mapped[Optional[StaffUser]] = relationship()
    claim_token: Mapped[Optional[str]] = mapped_column(String(64), unique=True, nullable=True)
    staff_reply: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    audio_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    transcript: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    client_uuid: Mapped[Optional[str]] = mapped_column(String(64), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    claimed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reserved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class BedCapacity(Base):
    __tablename__ = "bed_capacity"
    id: Mapped[int] = mapped_column(primary_key=True)
    total_beds: Mapped[int] = mapped_column(Integer, default=4)
    available_beds: Mapped[int] = mapped_column(Integer, default=4)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("staff_users.id"), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("staff_users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    entity: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ============================================================================
# SCHEMAS
# ============================================================================
class LoginIn(BaseModel):
    phone: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    name: str


class StaffCreate(BaseModel):
    name: str
    phone: str
    password: str
    role: str = "staff"


class StaffOut(BaseModel):
    id: int
    name: str
    phone: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class RequestOut(BaseModel):
    id: int
    patient_phone: str
    patient_name: Optional[str]
    message: str
    channel: str
    status: str
    claimed_by_id: Optional[int]
    claimed_by_name: Optional[str] = None
    claim_token: Optional[str]
    created_at: datetime
    claimed_at: Optional[datetime]
    reserved_at: Optional[datetime]
    staff_reply: Optional[str]
    transcript: Optional[str]

    class Config:
        from_attributes = True


class ClaimOut(BaseModel):
    claim_token: str
    request: RequestOut


class ReplyIn(BaseModel):
    claim_token: str
    staff_reply: str
    reserve_bed: bool = True


class BedOut(BaseModel):
    total_beds: int
    available_beds: int
    updated_at: datetime

    class Config:
        from_attributes = True


class BedUpdate(BaseModel):
    total_beds: Optional[int] = None
    available_beds: Optional[int] = None


class IngestIn(BaseModel):
    patient_phone: str
    message: str
    channel: str = "sms"
    patient_name: Optional[str] = None
    client_uuid: Optional[str] = None
    transcript: Optional[str] = None
    audio_url: Optional[str] = None


# ============================================================================
# SECURITY
# ============================================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)


def create_access_token(subject: str, role: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN)
    return jwt.encode({"sub": subject, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> StaffUser:
    exc = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise exc
    user = db.query(StaffUser).filter(StaffUser.phone == payload.get("sub")).first()
    if not user or not user.is_active:
        raise exc
    return user


def require_admin(user: StaffUser = Depends(current_user)) -> StaffUser:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin only")
    return user


# ============================================================================
# SMS SENDER
# ============================================================================
async def send_sms(to: str, message: str) -> dict:
    if not AT_API_KEY or not AT_USERNAME:
        print(f"[SMS-DEV] to={to} msg={message!r}")
        return {"SMSMessageData": {"Recipients": [{"status": "dev-mode"}]}}
    headers = {"apiKey": AT_API_KEY, "Accept": "application/json"}
    data = {"username": AT_USERNAME, "to": to, "message": message}
    if AT_SENDER_ID:
        data["from"] = AT_SENDER_ID
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post("https://api.africastalking.com/version1/messaging",
                              headers=headers, data=data)
        return r.json()


# ============================================================================
# HELPERS
# ============================================================================
def serialize_request(req: BedRequest) -> RequestOut:
    out = RequestOut.model_validate(req)
    out.claimed_by_name = req.claimed_by.name if req.claimed_by else None
    return out


def get_or_create_capacity(db: Session) -> BedCapacity:
    cap = db.query(BedCapacity).first()
    if not cap:
        cap = BedCapacity(total_beds=4, available_beds=4)
        db.add(cap); db.commit(); db.refresh(cap)
    return cap


# ============================================================================
# APP
# ============================================================================
app = FastAPI(title="JK Pancrass Emergency Bed System", version="0.1.0")


@app.on_event("startup")
def _startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(StaffUser).first():
            db.add_all([
                StaffUser(name="Dr. Admin", phone="+256700000001",
                          password_hash=hash_password("admin123"), role="admin"),
                StaffUser(name="Nurse Sarah", phone="+256700000002",
                          password_hash=hash_password("staff123"), role="staff"),
            ])
        if not db.query(BedCapacity).first():
            db.add(BedCapacity(total_beds=4, available_beds=4))
        if not db.query(BedRequest).first():
            db.add(BedRequest(
                patient_phone="+256700000099",
                message="Labour, bleeding heavily",
                channel="sms",
                status="pending",
            ))
        db.commit()
    finally:
        db.close()


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ----------------------------------------------------------------------------
# AUTH
# ----------------------------------------------------------------------------
@app.post("/api/auth/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(StaffUser).filter(
        StaffUser.phone == payload.phone, StaffUser.is_active.is_(True)
    ).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid phone or password")
    return TokenOut(access_token=create_access_token(user.phone, user.role),
                    role=user.role, name=user.name)


# ----------------------------------------------------------------------------
# STAFF MANAGEMENT (admin only)
# ----------------------------------------------------------------------------
@app.get("/api/staff", response_model=list[StaffOut])
def list_staff(db: Session = Depends(get_db), _: StaffUser = Depends(require_admin)):
    return db.query(StaffUser).order_by(StaffUser.id).all()


@app.post("/api/staff", response_model=StaffOut)
def create_staff(payload: StaffCreate, db: Session = Depends(get_db),
                 admin: StaffUser = Depends(require_admin)):
    if payload.role not in ("admin", "staff"):
        raise HTTPException(400, "Invalid role")
    if db.query(StaffUser).filter(StaffUser.phone == payload.phone).first():
        raise HTTPException(409, "Phone already registered")
    user = StaffUser(name=payload.name, phone=payload.phone,
                     password_hash=hash_password(payload.password), role=payload.role)
    db.add(user); db.commit(); db.refresh(user)
    db.add(AuditLog(actor_id=admin.id, action="staff_create", entity="staff_user", entity_id=user.id))
    db.commit()
    return user


@app.delete("/api/staff/{staff_id}")
def deactivate_staff(staff_id: int, db: Session = Depends(get_db),
                     admin: StaffUser = Depends(require_admin)):
    user = db.query(StaffUser).filter(StaffUser.id == staff_id).first()
    if not user:
        raise HTTPException(404, "Not found")
    if user.id == admin.id:
        raise HTTPException(400, "Cannot deactivate yourself")
    user.is_active = False
    db.add(AuditLog(actor_id=admin.id, action="staff_deactivate", entity="staff_user", entity_id=user.id))
    db.commit()
    return {"ok": True}


# ----------------------------------------------------------------------------
# BEDS
# ----------------------------------------------------------------------------
@app.get("/api/beds", response_model=BedOut)
def read_beds(db: Session = Depends(get_db), _: StaffUser = Depends(current_user)):
    return get_or_create_capacity(db)


@app.patch("/api/beds", response_model=BedOut)
def update_beds(payload: BedUpdate, db: Session = Depends(get_db),
                admin: StaffUser = Depends(require_admin)):
    cap = get_or_create_capacity(db)
    if payload.total_beds is not None:
        if payload.total_beds < 0:
            raise HTTPException(400, "total_beds must be >= 0")
        cap.total_beds = payload.total_beds
        cap.available_beds = min(cap.available_beds, cap.total_beds)
    if payload.available_beds is not None:
        if not (0 <= payload.available_beds <= cap.total_beds):
            raise HTTPException(400, "available_beds must be between 0 and total_beds")
        cap.available_beds = payload.available_beds
    cap.updated_at = datetime.utcnow()
    cap.updated_by_id = admin.id
    db.add(AuditLog(actor_id=admin.id, action="beds_update", entity="bed_capacity", entity_id=cap.id))
    db.commit(); db.refresh(cap)
    return cap


# ----------------------------------------------------------------------------
# REQUESTS (queue)
# ----------------------------------------------------------------------------
@app.get("/api/requests", response_model=list[RequestOut])
def list_requests(status_filter: Optional[str] = None,
                  db: Session = Depends(get_db),
                  user: StaffUser = Depends(current_user)):
    q = db.query(BedRequest).order_by(BedRequest.created_at.desc())
    if user.role != "admin":
        q = q.filter(BedRequest.status.in_(["pending", "claimed", "bed_reserved"]))
    if status_filter:
        q = q.filter(BedRequest.status == status_filter)
    return [serialize_request(r) for r in q.limit(200).all()]


@app.post("/api/requests/ingest", response_model=RequestOut)
def ingest(payload: IngestIn, db: Session = Depends(get_db),
           x_ingest_key: Optional[str] = Header(default=None)):
    if INGEST_KEY and x_ingest_key != INGEST_KEY:
        raise HTTPException(401, "Invalid ingest key")
    if payload.client_uuid:
        existing = db.query(BedRequest).filter(BedRequest.client_uuid == payload.client_uuid).first()
        if existing:
            return serialize_request(existing)
    req = BedRequest(patient_phone=payload.patient_phone, patient_name=payload.patient_name,
                     message=payload.message, channel=payload.channel, status="pending",
                     client_uuid=payload.client_uuid, transcript=payload.transcript,
                     audio_url=payload.audio_url)
    db.add(req); db.commit(); db.refresh(req)
    return serialize_request(req)


@app.post("/api/requests/{req_id}/claim", response_model=ClaimOut)
def claim_request(req_id: int, db: Session = Depends(get_db),
                  user: StaffUser = Depends(current_user)):
    req = db.query(BedRequest).filter(BedRequest.id == req_id).first()
    if not req:
        raise HTTPException(404, "Not found")
    if req.status == "claimed" and req.claimed_by_id != user.id:
        other = req.claimed_by.name if req.claimed_by else "another staff"
        raise HTTPException(409, f"Already claimed by {other}")
    if req.status not in ("pending", "claimed"):
        raise HTTPException(409, f"Request is {req.status}")
    token = uuid.uuid4().hex
    req.status = "claimed"
    req.claimed_by_id = user.id
    req.claimed_at = datetime.utcnow()
    req.claim_token = token
    db.add(AuditLog(actor_id=user.id, action="claim", entity="bed_request", entity_id=req.id))
    db.commit(); db.refresh(req)
    return ClaimOut(claim_token=token, request=serialize_request(req))


@app.post("/api/requests/{req_id}/reply", response_model=RequestOut)
async def reply_request(req_id: int, payload: ReplyIn, db: Session = Depends(get_db),
                        user: StaffUser = Depends(current_user)):
    req = db.query(BedRequest).filter(BedRequest.id == req_id).first()
    if not req:
        raise HTTPException(404, "Not found")
    if req.claim_token != payload.claim_token:
        raise HTTPException(409, "You do not hold this claim")
    if req.status not in ("claimed", "bed_reserved"):
        raise HTTPException(409, f"Cannot reply in status {req.status}")
    cap = get_or_create_capacity(db)
    if payload.reserve_bed and cap.available_beds <= 0:
        raise HTTPException(409, "No beds available")
    try:
        await send_sms(req.patient_phone, payload.staff_reply)
    except Exception as exc:
        print("SMS send failed:", exc)
    req.staff_reply = payload.staff_reply
    if payload.reserve_bed:
        req.status = "bed_reserved"
        req.reserved_at = datetime.utcnow()
        cap.available_beds -= 1
        cap.updated_at = datetime.utcnow()
    db.add(AuditLog(actor_id=user.id, action="reply", entity="bed_request",
                    entity_id=req.id, detail=payload.staff_reply[:300]))
    db.commit(); db.refresh(req)
    return serialize_request(req)


@app.post("/api/requests/{req_id}/complete", response_model=RequestOut)
def complete_request(req_id: int, db: Session = Depends(get_db),
                     admin: StaffUser = Depends(require_admin)):
    req = db.query(BedRequest).filter(BedRequest.id == req_id).first()
    if not req:
        raise HTTPException(404, "Not found")
    if req.status == "bed_reserved":
        cap = get_or_create_capacity(db)
        cap.available_beds = min(cap.total_beds, cap.available_beds + 1)
        cap.updated_at = datetime.utcnow()
    req.status = "completed"
    db.add(AuditLog(actor_id=admin.id, action="complete", entity="bed_request", entity_id=req.id))
    db.commit(); db.refresh(req)
    return serialize_request(req)


# ----------------------------------------------------------------------------
# WEBHOOKS (Africa's Talking)
# ----------------------------------------------------------------------------
# --- Lusoga translations (manual, MVP) ---
LUSOGA = {
    "welcome": "Tukusanyukidde ku JK Pancrass\n1. Teekateeka kitanda ky'amangu\n2. Yita musawo",
    "ask_emergency": "Ekizibu ki?\n1. Okwenda / okuvaamu omusaayi\n2. Omwana mulwadde nnyo\n3. Akabenje / obuvune\n4. Ekizibu kirala",
    "call_clinic": "Yita JK Pancrass kaakano: +256 700 000 000",
    "invalid": "Ekifo kino tekikkirizibwa",
    "request_sent": "Okusaba kwo kutumiddwa. Jja ku JK Pancrass kaakano — ddwaliro liteekateeka.",
    "end": "Olukiiko lukomekeddwa",
    "sms_confirm": "Okusaba kwo kutuuse ku JK Pancrass. Jja mangu. Musawo ajja kuddamu.",
    "sms_received": "Obubaka bwo butuuse. Musawo ajja kuddamu mangu.",
}


@app.post("/api/webhooks/sms")
async def sms_incoming(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    phone = (form.get("from") or "").strip()
    text = (form.get("text") or "").strip()
    if not phone:
        return PlainTextResponse("missing from", status_code=400)
    lowered = text.lower()
    if lowered.startswith("bed") or lowered == "1" or "emergency" in lowered:
        parts = text.split(" ", 1)
        body = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "Emergency bed request"
        db.add(BedRequest(patient_phone=phone, message=body, channel="sms", status="pending"))
        db.commit()
        await send_sms(phone, LUSOGA["sms_confirm"])
        return PlainTextResponse("ok")
    db.add(BedRequest(patient_phone=phone, message=text, channel="sms", status="pending"))
    db.commit()
    await send_sms(phone, LUSOGA["sms_received"])
    return PlainTextResponse("ok")


async def _handle_ussd(phone: str, text: str, db: Session) -> str:
    segments = text.split("*") if text else []
    depth = len(segments)
    if depth == 0:
        return f"CON {LUSOGA['welcome']}"
    if depth == 1:
        if segments[0] == "1":
            return f"CON {LUSOGA['ask_emergency']}"
        if segments[0] == "2":
            return f"END {LUSOGA['call_clinic']}"
        return f"END {LUSOGA['invalid']}"
    if depth == 2 and segments[0] == "1":
        mapping = {
            "1": "Okwenda / okuvaamu omusaayi",
            "2": "Omwana mulwadde nnyo",
            "3": "Aabenje / obuvune",
            "4": "Ekizibu kirala",
        }
        msg = mapping.get(segments[1], "Ekizibu")
        db.add(BedRequest(patient_phone=phone, message=msg, channel="ussd", status="pending"))
        db.commit()
        return f"END {LUSOGA['request_sent']}"
    return f"END {LUSOGA['end']}"


@app.post("/api/webhooks/ussd")
async def ussd_callback(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    phone = (form.get("phoneNumber") or "").strip()
    text = (form.get("text") or "").strip()
    body = await _handle_ussd(phone, text, db)
    return PlainTextResponse(body, media_type="text/plain")


# ============================================================================
# FRONTEND (served inline)
# ============================================================================
INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="theme-color" content="#b91c1c"/>
<title>JK Pancrass — Emergency Beds</title>
<link rel="manifest" href="/manifest.json"/>
<style>
body{font-family:system-ui,sans-serif;margin:0;background:#f4f4f5;color:#111}
header{background:#b91c1c;color:#fff;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}
header h1{font-size:15px;margin:0}
.pill{padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}
.online{background:#16a34a}.offline{background:#525252}
main{max-width:900px;margin:0 auto;padding:16px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px;margin-bottom:12px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.card.pending{border-left:4px solid #f59e0b}
.card.claimed{border-left:4px solid #2563eb}
.card.bed_reserved{border-left:4px solid #16a34a;opacity:.85}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.muted{color:#6b7280;font-size:12px}
button{background:#b91c1c;color:#fff;border:none;border-radius:8px;padding:9px 14px;font-size:14px;cursor:pointer}
button.secondary{background:#374151}
button:disabled{opacity:.5;cursor:not-allowed}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;margin-bottom:8px}
.beds{display:flex;gap:8px;align-items:center;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:12px;margin-bottom:14px}
.beds .num{font-size:28px;font-weight:700}
.alert{background:#fee2e2;color:#991b1b;padding:12px;border-radius:10px;margin-bottom:14px;font-weight:600}
.badge{background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:6px;font-size:12px}
.hidden{display:none}
</style>
</head>
<body>
<header><h1>JK Pancrass — Emergency Beds</h1><span id="net" class="pill offline">offline</span></header>
<main>
<section id="loginView">
  <div class="card">
    <h2 style="margin-top:0">Staff login</h2>
    <input id="phone" placeholder="Phone (+256700000001)" autocomplete="username"/>
    <input id="password" type="password" placeholder="Password" autocomplete="current-password"/>
    <button id="loginBtn">Log in</button>
    <p class="muted">Demo: admin +256700000001/admin123 · staff +256700000002/staff123</p>
    <p id="loginErr" class="muted" style="color:#b91c1c"></p>
  </div>
</section>
<section id="appView" class="hidden">
  <div id="noBeds" class="alert hidden">⚠️ NO BEDS AVAILABLE — Refer patients to Mayuge HC IV</div>
  <div class="beds">
    <div><div class="muted">Available beds</div><div class="num" id="avail">–</div></div>
    <div style="margin-left:auto;text-align:right"><div class="muted">Total</div><div id="total">–</div></div>
    <div class="row" id="adminBeds" style="margin-left:16px">
      <input id="bedsInput" type="number" min="0" style="width:90px;margin:0" placeholder="Total"/>
      <button class="secondary" id="setBeds">Set</button>
    </div>
  </div>
  <div class="row" style="margin-bottom:12px">
    <strong>Incoming requests</strong>
    <button class="secondary" id="refresh" style="margin-left:auto">Refresh</button>
    <button class="secondary" id="logout">Log out</button>
  </div>
  <div id="queue"></div>
</section>
</main>
<script src="/static/app.js"></script>
</body>
</html>
"""

APP_JS = """
const $ = (id) => document.getElementById(id);
const state = {
  token: localStorage.getItem("token") || null,
  role: localStorage.getItem("role") || null,
  name: localStorage.getItem("name") || null,
  requests: [],
  pendingClaim: {},
  outbox: JSON.parse(localStorage.getItem("outbox") || "[]"),
};
function persist(){
  localStorage.setItem("token", state.token || "");
  localStorage.setItem("role", state.role || "");
  localStorage.setItem("name", state.name || "");
  localStorage.setItem("outbox", JSON.stringify(state.outbox));
}
function authHeaders(){
  const h = {"Content-Type":"application/json"};
  if (state.token) h["Authorization"] = `Bearer ${state.token}`;
  return h;
}
async function api(path, opts = {}){
  const res = await fetch(path, {...opts, headers: {...authHeaders(), ...(opts.headers||{})}});
  if (res.status === 401){ logout(); throw new Error("Session expired"); }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && (data.detail || data.message)) || res.statusText);
  return data;
}
function setNet(){
  const el = $("net");
  if (navigator.onLine){ el.textContent="online"; el.className="pill online"; }
  else { el.textContent="offline"; el.className="pill offline"; }
}
window.addEventListener("online", () => { setNet(); flushOutbox(); });
window.addEventListener("offline", setNet);
function logout(){
  state.token = state.role = state.name = null;
  persist();
  $("appView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
}
$("loginBtn").onclick = async () => {
  try {
    const data = await api("/api/auth/login", {method:"POST", body: JSON.stringify({phone: $("phone").value.trim(), password: $("password").value})});
    state.token = data.access_token; state.role = data.role; state.name = data.name;
    persist(); await enterApp();
  } catch (e){ $("loginErr").textContent = e.message; }
};
$("logout").onclick = logout;
$("refresh").onclick = loadAll;
async function enterApp(){
  $("loginView").classList.add("hidden");
  $("appView").classList.remove("hidden");
  $("adminBeds").style.display = state.role === "admin" ? "flex" : "none";
  await loadAll();
}
$("setBeds").onclick = async () => {
  const v = parseInt($("bedsInput").value, 10);
  if (isNaN(v) || v < 0) return;
  try { await api("/api/beds", {method:"PATCH", body: JSON.stringify({total_beds: v, available_beds: v})}); await loadAll(); }
  catch (e){ alert(e.message); }
};
async function loadAll(){
  try {
    const [beds, reqs] = await Promise.all([api("/api/beds"), api("/api/requests")]);
    state.requests = reqs;
    $("avail").textContent = beds.available_beds;
    $("total").textContent = beds.total_beds;
    $("noBeds").classList.toggle("hidden", beds.available_beds > 0);
    renderQueue();
  } catch (e){ console.warn("load failed", e); }
}
function renderQueue(){
  const q = $("queue"); q.innerHTML = "";
  if (!state.requests.length){ q.innerHTML = '<p class="muted">No incoming requests.</p>'; return; }
  for (const r of state.requests){
    const el = document.createElement("div");
    el.className = `card ${r.status}`;
    const when = new Date(r.created_at + "Z").toLocaleString();
    el.innerHTML = `
      <div class="row">
        <strong>${escape(r.patient_name || r.patient_phone)}</strong>
        <span class="badge">${r.channel.toUpperCase()}</span>
        <span class="badge">${r.status.replace("_"," ")}</span>
        <span class="muted" style="margin-left:auto">${when}</span>
      </div>
      <p style="margin:8px 0">${escape(r.message)}</p>
      ${r.transcript ? `<p class="muted">Transcript: ${escape(r.transcript)}</p>` : ""}
      ${r.staff_reply ? `<p class="muted">Reply: ${escape(r.staff_reply)}</p>` : ""}
      <div class="row act"></div>`;
    const act = el.querySelector(".act");
    if (r.status === "pending"){
      const b = document.createElement("button"); b.textContent = "Claim";
      b.onclick = () => claim(r.id); act.appendChild(b);
    } else if (r.status === "claimed" && r.claimed_by_name === state.name){
      const b = document.createElement("button"); b.textContent = "Reply & reserve bed";
      b.onclick = () => replyFlow(r.id); act.appendChild(b);
    } else if (r.status === "claimed"){
      act.innerHTML = `<span class="muted">Claimed by ${escape(r.claimed_by_name || "another staff")}</span>`;
    } else if (r.status === "bed_reserved"){
      act.innerHTML = `<span class="muted">Bed reserved${r.reserved_at ? " · " + new Date(r.reserved_at + "Z").toLocaleTimeString() : ""}</span>`;
    }
    q.appendChild(el);
  }
}
async function claim(reqId){
  try {
    const data = await api(`/api/requests/${reqId}/claim`, {method:"POST"});
    state.pendingClaim[reqId] = data.claim_token;
    await loadAll();
  } catch (e){
    if (!navigator.onLine){
      state.outbox.push({op:"claim", reqId, at: Date.now()}); persist();
      alert("Offline — claim queued. Will retry when back online.");
    } else { alert(e.message); await loadAll(); }
  }
}
async function replyFlow(reqId){
  const r = state.requests.find((x) => x.id === reqId);
  const token = (r && r.claim_token) || state.pendingClaim[reqId];
  if (!token){ alert("Missing claim token — please refresh and claim again."); return; }
  const text = prompt("Reply to patient (an SMS will be sent):", "We are preparing a bed for you. Please come to JK Pancrass now.");
  if (!text) return;
  const reserve = confirm("Reserve a bed for this patient? (OK = yes)");
  const body = {claim_token: token, staff_reply: text, reserve_bed: reserve};
  try {
    await api(`/api/requests/${reqId}/reply`, {method:"POST", body: JSON.stringify(body)});
    await loadAll();
  } catch (e){
    if (!navigator.onLine){
      state.outbox.push({op:"reply", reqId, body, at: Date.now()}); persist();
      alert("Offline — reply queued. Will send when back online.");
    } else { alert(e.message); }
  }
}
async function flushOutbox(){
  if (!state.outbox.length) return;
  const remaining = [];
  for (const item of state.outbox){
    try {
      if (item.op === "claim"){
        const data = await api(`/api/requests/${item.reqId}/claim`, {method:"POST"});
        state.pendingClaim[item.reqId] = data.claim_token;
      } else if (item.op === "reply"){
        await api(`/api/requests/${item.reqId}/reply`, {method:"POST", body: JSON.stringify(item.body)});
      }
    } catch (e){ remaining.push(item); }
  }
  state.outbox = remaining; persist(); await loadAll();
}
function escape(s){
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c]));
}
setNet();
if (state.token) enterApp(); else $("loginView").classList.remove("hidden");
if ("serviceWorker" in navigator){ navigator.serviceWorker.register("/sw.js").catch(()=>{}); }
"""

SW_JS = """
const CACHE = "jkp-beds-v1";
const SHELL = ["/", "/static/app.js", "/manifest.json"];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(()=>{}));
  self.skipWaiting();
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) =>
    Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
  ));
  self.clients.claim();
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/api/") && e.request.method === "GET"){
    e.respondWith(fetch(e.request).then((res) => {
      const copy = res.clone();
      caches.open(CACHE).then((c) => c.put(e.request, copy));
      return res;
    }).catch(() => caches.match(e.request)));
    return;
  }
  if (e.request.method === "GET"){
    e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request)));
  }
});
"""

MANIFEST = {
    "name": "JK Pancrass Emergency Beds",
    "short_name": "JKP Beds",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#f4f4f5",
    "theme_color": "#b91c1c",
    "icons": [],
}


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


@app.get("/static/app.js")
def app_js():
    return Response(APP_JS, media_type="application/javascript")


@app.get("/sw.js")
def sw_js():
    return Response(SW_JS, media_type="application/javascript")


@app.get("/manifest.json")
def manifest():
    return MANIFEST


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)
