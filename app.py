import os, secrets, hashlib, hmac
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, DateTime, ForeignKey, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./local.db')
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
JWT_SECRET = os.getenv('JWT_SECRET', '')
LICENSE_SECRET = os.getenv('LICENSE_SECRET', '')
if not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 12 or len(JWT_SECRET) < 32 or len(LICENSE_SECRET) < 32:
    raise RuntimeError('Configure ADMIN_PASSWORD (12+), JWT_SECRET (32+) e LICENSE_SECRET (32+) no .env')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase): pass
class Client(Base):
    __tablename__ = 'clients'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150))
    email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
class License(Base):
    __tablename__ = 'licenses'
    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey('clients.id'))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_hint: Mapped[str] = mapped_column(String(16))
    mt5_login: Mapped[str] = mapped_column(String(30))
    mt5_server: Mapped[str] = mapped_column(String(150))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    blocked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
class Audit(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(80))
    license_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(String(300), default='')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
app = FastAPI(title='ROBOCARDANI License Manager', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=Path(__file__).parent / 'static'), name='static')

def db():
    with SessionLocal() as session: yield session

def now(): return datetime.now(timezone.utc)
def utc(value): return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value
def key_digest(key): return hmac.new(LICENSE_SECRET.encode(), key.encode(), hashlib.sha256).hexdigest()

def admin(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith('Bearer '): raise HTTPException(401, 'Autenticação necessária')
    try:
        data = jwt.decode(authorization[7:], JWT_SECRET, algorithms=['HS256'], issuer='robocardani')
        if data.get('sub') != ADMIN_USER or data.get('role') != 'admin': raise ValueError()
    except Exception: raise HTTPException(401, 'Sessão inválida ou expirada')
    return True

class LoginIn(BaseModel):
    username: str
    password: str
class ClientIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    email: Optional[str] = Field(default=None, max_length=200)
class LicenseIn(BaseModel):
    client_id: int
    mt5_login: str = Field(pattern=r'^\d{1,30}$')
    mt5_server: str = Field(min_length=1, max_length=150)
    days: Optional[int] = Field(default=30, ge=1, le=3650)
class RenewIn(BaseModel):
    days: int = Field(ge=1, le=3650)
class ValidateIn(BaseModel):
    license_key: str = Field(min_length=15, max_length=120)
    mt5_login: str
    mt5_server: str

def license_json(l):
    return {'id': l.id, 'client_id': l.client_id, 'key_hint': l.key_hint, 'mt5_login': l.mt5_login, 'mt5_server': l.mt5_server, 'expires_at': utc(l.expires_at).isoformat() if l.expires_at else None, 'blocked': l.blocked, 'status': 'blocked' if l.blocked else 'expired' if l.expires_at and utc(l.expires_at) <= now() else 'active'}

@app.get('/')
def home(): return FileResponse(Path(__file__).parent / 'static' / 'index.html')

@app.post('/api/admin/login')
def login(body: LoginIn):
    if not (secrets.compare_digest(body.username, ADMIN_USER) and secrets.compare_digest(body.password, ADMIN_PASSWORD)):
        raise HTTPException(401, 'Credenciais incorretas')
    token = jwt.encode({'sub': ADMIN_USER, 'role': 'admin', 'iss': 'robocardani', 'iat': now(), 'exp': now() + timedelta(hours=4)}, JWT_SECRET, algorithm='HS256')
    return {'access_token': token, 'token_type': 'bearer', 'expires_in': 14400}

@app.get('/api/admin/clients', dependencies=[Depends(admin)])
def clients(session: Session = Depends(db)):
    return [{'id': c.id, 'name': c.name, 'email': c.email} for c in session.scalars(select(Client).order_by(Client.id.desc())).all()]

@app.post('/api/admin/clients', dependencies=[Depends(admin)])
def add_client(body: ClientIn, session: Session = Depends(db)):
    c = Client(name=body.name.strip(), email=body.email)
    session.add(c); session.commit(); session.refresh(c)
    return {'id': c.id, 'name': c.name, 'email': c.email}

@app.get('/api/admin/licenses', dependencies=[Depends(admin)])
def licenses(session: Session = Depends(db)):
    rows = session.execute(select(License, Client.name).join(Client).order_by(License.id.desc())).all()
    return [dict(license_json(l), client_name=name) for l, name in rows]

@app.post('/api/admin/licenses', dependencies=[Depends(admin)])
def add_license(body: LicenseIn, session: Session = Depends(db)):
    if not session.get(Client, body.client_id): raise HTTPException(404, 'Cliente não encontrado')
    raw = 'RC-' + secrets.token_urlsafe(30)
    l = License(client_id=body.client_id, key_hash=key_digest(raw), key_hint=raw[-8:], mt5_login=body.mt5_login, mt5_server=body.mt5_server.strip(), expires_at=now() + timedelta(days=body.days) if body.days is not None else None)
    session.add(l); session.flush(); session.add(Audit(action='created', license_id=l.id)); session.commit(); session.refresh(l)
    return dict(license_json(l), license_key=raw, notice='Copie agora. A chave não poderá ser consultada novamente.')

@app.post('/api/admin/licenses/{license_id}/block', dependencies=[Depends(admin)])
def block(license_id: int, session: Session = Depends(db)):
    l = session.get(License, license_id)
    if not l: raise HTTPException(404, 'Licença não encontrada')
    l.blocked = True; session.add(Audit(action='blocked', license_id=l.id)); session.commit()
    return license_json(l)

@app.post('/api/admin/licenses/{license_id}/unblock', dependencies=[Depends(admin)])
def unblock(license_id: int, session: Session = Depends(db)):
    l = session.get(License, license_id)
    if not l: raise HTTPException(404, 'Licença não encontrada')
    l.blocked = False; session.add(Audit(action='unblocked', license_id=l.id)); session.commit()
    return license_json(l)

@app.post('/api/admin/licenses/{license_id}/renew', dependencies=[Depends(admin)])
def renew(license_id: int, body: RenewIn, session: Session = Depends(db)):
    l = session.get(License, license_id)
    if not l: raise HTTPException(404, 'Licença não encontrada')
    base = max(now(), utc(l.expires_at)) if l.expires_at else now()
    l.expires_at = base + timedelta(days=body.days)
    session.add(Audit(action='renewed', license_id=l.id, detail=f'{body.days} days')); session.commit()
    return license_json(l)

@app.get('/api/admin/audit', dependencies=[Depends(admin)])
def audit(session: Session = Depends(db)):
    return [{'action': a.action, 'license_id': a.license_id, 'detail': a.detail, 'created_at': utc(a.created_at).isoformat()} for a in session.scalars(select(Audit).order_by(Audit.id.desc()).limit(100)).all()]

@app.post('/api/v1/validate')
def validate(body: ValidateIn, session: Session = Depends(db)):
    l = session.scalar(select(License).where(License.key_hash == key_digest(body.license_key)))
    # Do not reveal whether a key exists or which field failed.
    valid = bool(l and not l.blocked and (not l.expires_at or utc(l.expires_at) > now()) and secrets.compare_digest(l.mt5_login, body.mt5_login) and secrets.compare_digest(l.mt5_server, body.mt5_server))
    return {'valid': valid, 'server_time': now().isoformat()}

@app.get('/health')
def health(): return {'status': 'ok'}
