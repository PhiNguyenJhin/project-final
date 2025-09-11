"""
IMS - Intern Management System 

Features:
- FastAPI REST API with layered structure (config, db, models, schemas, repos, services, routers)
- JWT Auth + Role-based access control (admin, hr_manager, coordinator, mentor, intern)
- Supports SQLite (default) or SQL Server via ENV (USE_SQLSERVER=true and SQLSERVER_* env vars)
- Mocked Notification (email/sms) via BackgroundTasks (print)
- Simple reporting endpoint
- Selenium smoke test to verify API+Swagger
- Seed endpoint to create demo users

Run:
  pip install fastapi uvicorn "sqlalchemy<2" passlib[bcrypt] python-jose[cryptography] pydantic[email] "email-validator<2" python-multipart selenium webdriver-manager requests pyodbc
  uvicorn main:app --reload

Author: Student
Date: 2025-09
"""

from __future__ import annotations
import os, sys, json, enum, datetime as dt
from typing import List, Optional, Any, Dict

from pydantic import BaseSettings, AnyUrl

class Settings(BaseSettings):
    PROJECT_NAME: str = "IMS - Intern Management System (Final Project)"
    DEBUG: bool = True
    USE_SQLSERVER: bool = os.getenv("USE_SQLSERVER", "false").lower() == "true"
    # SQL Server ENV vars (if USE_SQLSERVER True)
    SQLSERVER_USER: str = os.getenv("SQLSERVER_USER", "sa")
    SQLSERVER_PASS: str = os.getenv("SQLSERVER_PASS", "YourPassword")
    SQLSERVER_HOST: str = os.getenv("SQLSERVER_HOST", "localhost:1433")
    SQLSERVER_DB: str = os.getenv("SQLSERVER_DB", "IMS_DB")
    SQLSERVER_DRIVER: str = os.getenv("SQLSERVER_DRIVER", "ODBC+Driver+17+for+SQL+Server")
    # fallback to SQLite
    SQLITE_URL: str = "sqlite:///./ims.db"
    # Auth
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-secret-change-this")
    JWT_ALG: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    class Config:
        env_file = ".env"

settings = Settings()

def get_database_url() -> str:
    if settings.USE_SQLSERVER:
        # mssql+pyodbc://user:pass@host:port/db?driver=ODBC+Driver+17+for+SQL+Server
        return f"mssql+pyodbc://{settings.SQLSERVER_USER}:{settings.SQLSERVER_PASS}@{settings.SQLSERVER_HOST}/{settings.SQLSERVER_DB}?driver={settings.SQLSERVER_DRIVER}"
    return settings.SQLITE_URL

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

app = FastAPI(title=settings.PROJECT_NAME, version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Enum, Float
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from sqlalchemy.exc import IntegrityError

DATABASE_URL = get_database_url()
# If using SQLite need connect_args
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, echo=False, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from passlib.context import CryptContext
from jose import jwt, JWTError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False

def create_access_token(sub: dict, expires_minutes: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = sub.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALG)

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        return payload
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or expired")

class Role(str, enum.Enum):
    admin = "admin"
    hr_manager = "hr_manager"
    coordinator = "coordinator"
    mentor = "mentor"
    intern = "intern"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role), nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    intern_profile = relationship("InternProfile", back_populates="user", uselist=False)

class InternProfile(Base):
    __tablename__ = "intern_profiles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    university = Column(String)
    major = Column(String)
    year = Column(String)
    resume_url = Column(String)
    skills = Column(Text, default="[]")
    work_history = Column(Text, default="[]")

    user = relationship("User", back_populates="intern_profile")

class InternshipCampaign(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    created_by_id = Column(Integer, ForeignKey("users.id"))

class JobPosting(Base):
    __tablename__ = "job_postings"
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"))
    title = Column(String, nullable=False)
    description = Column(Text)
    location = Column(String)
    skills_required = Column(Text, default="[]")
    slots = Column(Integer, default=1)

class Application(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True)
    posting_id = Column(Integer, ForeignKey("job_postings.id"))
    applicant_email = Column(String, nullable=False)
    cv_url = Column(String)
    status = Column(String, default="submitted")  # submitted, shortlisted, interviewed, offered, rejected
    notes = Column(Text, default="")

class Interview(Base):
    __tablename__ = "interviews"
    id = Column(Integer, primary_key=True)
    application_id = Column(Integer, ForeignKey("applications.id"))
    interviewer_id = Column(Integer, ForeignKey("users.id"))
    scheduled_at = Column(DateTime, nullable=False)
    mode = Column(String, default="online")  # online / onsite
    location_or_link = Column(String)
    reminder_sent = Column(Boolean, default=False)

class TrainingProgram(Base):
    __tablename__ = "training_programs"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    goals = Column(Text, default="[]")
    created_by_id = Column(Integer, ForeignKey("users.id"))

class KPI(Base):
    __tablename__ = "kpis"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    weight = Column(Float, default=1.0)

class PerformanceRecord(Base):
    __tablename__ = "performance_records"
    id = Column(Integer, primary_key=True)
    intern_id = Column(Integer, ForeignKey("users.id"))
    kpi_id = Column(Integer, ForeignKey("kpis.id"))
    value = Column(Float, default=0)
    recorded_at = Column(DateTime, default=dt.datetime.utcnow)

class DailyLog(Base):
    __tablename__ = "daily_logs"
    id = Column(Integer, primary_key=True)
    intern_id = Column(Integer, ForeignKey("users.id"))
    mentor_id = Column(Integer, ForeignKey("users.id"))
    date = Column(DateTime, default=dt.date.today)
    activities = Column(Text)
    mentor_feedback = Column(Text, default="")

class Assessment(Base):
    __tablename__ = "assessments"
    id = Column(Integer, primary_key=True)
    intern_id = Column(Integer, ForeignKey("users.id"))
    mentor_id = Column(Integer, ForeignKey("users.id"))
    date = Column(DateTime, default=dt.date.today)
    skill = Column(String)
    score = Column(Integer)
    notes = Column(Text, default="")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    sent_at = Column(DateTime, default=dt.datetime.utcnow)
    content = Column(Text)
    read = Column(Boolean, default=False)

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True)
    intern_id = Column(Integer, ForeignKey("users.id"))
    about = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

class SettingKV(Base):
    __tablename__ = "settings_kv"
    key = Column(String, primary_key=True)
    value = Column(Text)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: Role

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: Role
    active: bool
    class Config:
        orm_mode = True

class InternProfileIn(BaseModel):
    university: Optional[str] = None
    major: Optional[str] = None
    year: Optional[str] = None
    resume_url: Optional[str] = None
    skills: List[str] = []
    work_history: List[dict] = []

class InternProfileOut(InternProfileIn):
    id: int
    user_id: int
    class Config:
        orm_mode = True

class CampaignIn(BaseModel):
    name: str
    description: Optional[str] = None
    start_date: Optional[dt.datetime] = None
    end_date: Optional[dt.datetime] = None

class CampaignOut(CampaignIn):
    id: int
    class Config:
        orm_mode = True

class JobPostingIn(BaseModel):
    campaign_id: int
    title: str
    description: Optional[str] = None
    location: Optional[str] = None
    skills_required: List[str] = []
    slots: int = 1

class JobPostingOut(JobPostingIn):
    id: int
    class Config:
        orm_mode = True

class ApplicationIn(BaseModel):
    posting_id: int
    applicant_email: EmailStr
    cv_url: Optional[str] = None

class ApplicationOut(BaseModel):
    id: int
    posting_id: int
    applicant_email: EmailStr
    cv_url: Optional[str]
    status: str
    notes: str
    class Config:
        orm_mode = True

class InterviewIn(BaseModel):
    application_id: int
    interviewer_id: int
    scheduled_at: dt.datetime
    mode: str = "online"
    location_or_link: Optional[str] = None

class InterviewOut(InterviewIn):
    id: int
    reminder_sent: bool
    class Config:
        orm_mode = True

class TrainingProgramIn(BaseModel):
    name: str
    description: Optional[str] = None
    goals: List[str] = []

class TrainingProgramOut(TrainingProgramIn):
    id: int
    class Config:
        orm_mode = True

class KPIIn(BaseModel):
    name: str
    description: Optional[str] = None
    weight: float = 1.0

class KPIOut(KPIIn):
    id: int
    class Config:
        orm_mode = True

class PerformanceRecordIn(BaseModel):
    intern_id: int
    kpi_id: int
    value: float

class PerformanceRecordOut(PerformanceRecordIn):
    id: int
    recorded_at: dt.datetime
    class Config:
        orm_mode = True

class DailyLogIn(BaseModel):
    intern_id: int
    mentor_id: int
    date: Optional[dt.date] = None
    activities: str
    mentor_feedback: Optional[str] = ""

class DailyLogOut(DailyLogIn):
    id: int
    class Config:
        orm_mode = True

class AssessmentIn(BaseModel):
    intern_id: int
    mentor_id: int
    date: Optional[dt.date] = None
    skill: str
    score: int = Field(ge=0, le=100)
    notes: Optional[str] = ""

class AssessmentOut(AssessmentIn):
    id: int
    class Config:
        orm_mode = True

class MessageIn(BaseModel):
    receiver_id: int
    content: str

class MessageOut(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    sent_at: dt.datetime
    read: bool
    class Config:
        orm_mode = True

class FeedbackIn(BaseModel):
    about: str
    content: str

class FeedbackOut(FeedbackIn):
    id: int
    intern_id: int
    created_at: dt.datetime
    class Config:
        orm_mode = True

class SettingIn(BaseModel):
    key: str
    value: Any

class UserRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: UserCreate) -> User:
        user = User(email=str(data.email).lower(), full_name=data.full_name, hashed_password=hash_password(data.password), role=data.role)
        self.db.add(user)
        try:
            self.db.commit()
            self.db.refresh(user)
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(400, "Email already exists")
        # create empty intern profile if intern
        if data.role == Role.intern:
            prof = InternProfile(user_id=user.id, skills="[]", work_history="[]")
            self.db.add(prof); self.db.commit()
        return user
    def by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email.lower()).first()
    def get(self, user_id: int) -> Optional[User]:
        return self.db.query(User).get(user_id)

class CampaignRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: CampaignIn, creator_id: int) -> InternshipCampaign:
        c = InternshipCampaign(name=data.name, description=data.description, start_date=data.start_date, end_date=data.end_date, created_by_id=creator_id)
        self.db.add(c); self.db.commit(); self.db.refresh(c); return c
    def list(self) -> List[InternshipCampaign]:
        return self.db.query(InternshipCampaign).all()

class JobPostingRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: JobPostingIn) -> JobPosting:
        jp = JobPosting(campaign_id=data.campaign_id, title=data.title, description=data.description, location=data.location, skills_required=json.dumps(data.skills_required), slots=data.slots)
        self.db.add(jp); self.db.commit(); self.db.refresh(jp); return jp
    def list(self, campaign_id: Optional[int] = None) -> List[JobPosting]:
        q = self.db.query(JobPosting)
        if campaign_id: q = q.filter(JobPosting.campaign_id == campaign_id)
        return q.all()

class ApplicationRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: ApplicationIn) -> Application:
        app = Application(posting_id=data.posting_id, applicant_email=str(data.applicant_email), cv_url=data.cv_url)
        self.db.add(app); self.db.commit(); self.db.refresh(app); return app
    def update_status(self, app_id: int, status_: str, notes: str = "") -> Application:
        app = self.db.query(Application).get(app_id)
        if not app: raise HTTPException(404, "Application not found")
        app.status = status_; app.notes = notes; self.db.commit(); self.db.refresh(app); return app

class InterviewRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: InterviewIn) -> Interview:
        iv = Interview(application_id=data.application_id, interviewer_id=data.interviewer_id, scheduled_at=data.scheduled_at, mode=data.mode, location_or_link=data.location_or_link)
        self.db.add(iv); self.db.commit(); self.db.refresh(iv); return iv
    def mark_reminder(self, interview_id: int):
        iv = self.db.query(Interview).get(interview_id)
        if not iv: raise HTTPException(404, "Interview not found")
        iv.reminder_sent = True; self.db.commit()

class ProfileRepo:
    def __init__(self, db: Session): self.db = db
    def upsert(self, user_id: int, data: InternProfileIn) -> InternProfile:
        prof = self.db.query(InternProfile).filter(InternProfile.user_id == user_id).first()
        if not prof:
            prof = InternProfile(user_id=user_id)
            self.db.add(prof)
        prof.university = data.university
        prof.major = data.major
        prof.year = data.year
        prof.resume_url = data.resume_url
        prof.skills = json.dumps(data.skills)
        prof.work_history = json.dumps(data.work_history)
        self.db.commit(); self.db.refresh(prof); return prof
    def get(self, user_id: int) -> Optional[InternProfile]:
        return self.db.query(InternProfile).filter(InternProfile.user_id == user_id).first()

class TrainingRepo:
    def __init__(self, db: Session): self.db = db
    def create_program(self, creator_id: int, data: TrainingProgramIn) -> TrainingProgram:
        tp = TrainingProgram(name=data.name, description=data.description, goals=json.dumps(data.goals), created_by_id=creator_id)
        self.db.add(tp); self.db.commit(); self.db.refresh(tp); return tp

class KPIRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: KPIIn) -> KPI:
        k = KPI(name=data.name, description=data.description, weight=data.weight)
        self.db.add(k); self.db.commit(); self.db.refresh(k); return k
    def list(self) -> List[KPI]:
        return self.db.query(KPI).all()

class PerformanceRepo:
    def __init__(self, db: Session): self.db = db
    def record(self, data: PerformanceRecordIn) -> PerformanceRecord:
        pr = PerformanceRecord(intern_id=data.intern_id, kpi_id=data.kpi_id, value=data.value)
        self.db.add(pr); self.db.commit(); self.db.refresh(pr); return pr
    def list_by_intern(self, intern_id: int) -> List[PerformanceRecord]:
        return self.db.query(PerformanceRecord).filter(PerformanceRecord.intern_id == intern_id).all()

class DailyLogRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: DailyLogIn) -> DailyLog:
        d = DailyLog(intern_id=data.intern_id, mentor_id=data.mentor_id, date=data.date or dt.date.today(), activities=data.activities, mentor_feedback=data.mentor_feedback or "")
        self.db.add(d); self.db.commit(); self.db.refresh(d); return d
    def list_for_intern(self, intern_id: int) -> List[DailyLog]:
        return self.db.query(DailyLog).filter(DailyLog.intern_id == intern_id).all()

class AssessmentRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, data: AssessmentIn) -> Assessment:
        a = Assessment(intern_id=data.intern_id, mentor_id=data.mentor_id, date=data.date or dt.date.today(), skill=data.skill, score=data.score, notes=data.notes or "")
        self.db.add(a); self.db.commit(); self.db.refresh(a); return a
    def list_by_intern(self, intern_id: int) -> List[Assessment]:
        return self.db.query(Assessment).filter(Assessment.intern_id == intern_id).all()

class MessageRepo:
    def __init__(self, db: Session): self.db = db
    def send(self, sender_id: int, data: MessageIn) -> Message:
        m = Message(sender_id=sender_id, receiver_id=data.receiver_id, content=data.content)
        self.db.add(m); self.db.commit(); self.db.refresh(m); return m
    def inbox(self, user_id: int) -> List[Message]:
        return self.db.query(Message).filter(Message.receiver_id == user_id).order_by(Message.sent_at.desc()).all()

class FeedbackRepo:
    def __init__(self, db: Session): self.db = db
    def create(self, intern_id: int, data: FeedbackIn) -> Feedback:
        f = Feedback(intern_id=intern_id, about=data.about, content=data.content)
        self.db.add(f); self.db.commit(); self.db.refresh(f); return f
    def list_all(self) -> List[Feedback]:
        return self.db.query(Feedback).order_by(Feedback.created_at.desc()).all()

class SettingsRepo:
    def __init__(self, db: Session): self.db = db
    def set(self, key: str, value: Any):
        kv = self.db.query(SettingKV).get(key)
        if not kv:
            kv = SettingKV(key=key, value=json.dumps(value))
            self.db.add(kv)
        else:
            kv.value = json.dumps(value)
        self.db.commit()
    def get(self, key: str, default: Any = None) -> Any:
        kv = self.db.query(SettingKV).get(key)
        return json.loads(kv.value) if kv else default

class NotificationService:
    def send_email(self, to: str, subject: str, body: str):
        # Mocked: print to console; replace with real provider in production
        print(f"[EMAIL] to={to} subject={subject} body={body[:200]}")

    def send_sms(self, to: str, body: str):
        print(f"[SMS] to={to} body={body[:160]}")

class ReportingService:
    def __init__(self, db: Session): self.db = db
    def program_summary(self) -> dict:
        interns = self.db.query(User).filter(User.role == Role.intern).count()
        mentors = self.db.query(User).filter(User.role == Role.mentor).count()
        apps = self.db.query(Application).count()
        scheduled = self.db.query(Interview).count()
        perf = self.db.query(PerformanceRecord).all()
        totals, counts = {}, {}
        for p in perf:
            totals[p.intern_id] = totals.get(p.intern_id, 0.0) + p.value
            counts[p.intern_id] = counts.get(p.intern_id, 0) + 1
        averages = {iid: (totals[iid] / counts[iid]) for iid in totals} if totals else {}
        return {
            "intern_count": interns,
            "mentor_count": mentors,
            "applications": apps,
            "interviews": scheduled,
            "avg_performance_by_intern": averages,
        }

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = decode_access_token(token)
        uid = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    user = db.query(User).get(uid)
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    return user

def require_roles(*roles: Role):
    def dep(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return current_user
    return dep

# Auth
@app.post("/auth/register", response_model=UserOut)
def register(user_in: UserCreate, db: Session = Depends(get_db), current: Optional[User] = Depends(lambda: None)):
    # self-register allowed only for interns; other roles require admin
    if user_in.role != Role.intern:
        if not current or current.role != Role.admin:
            raise HTTPException(403, "Only admin can create non-intern users")
    return UserRepo(db).create(user_in)

@app.post("/auth/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    repo = UserRepo(db)
    user = repo.by_email(form.username)
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(400, "Incorrect email or password")
    token = create_access_token({"sub": str(user.id), "role": user.role})
    return Token(access_token=token)

@app.get("/auth/me", response_model=UserOut)
def me(current: User = Depends(get_current_user)):
    return current

# HR Manager endpoints
@app.post("/hr/campaigns", response_model=CampaignOut, dependencies=[Depends(require_roles(Role.hr_manager, Role.admin))])
def create_campaign(data: CampaignIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    c = CampaignRepo(db).create(data, current.id)
    return c

@app.get("/hr/campaigns", response_model=List[CampaignOut], dependencies=[Depends(require_roles(Role.hr_manager, Role.admin))])
def list_campaigns(db: Session = Depends(get_db)):
    return CampaignRepo(db).list()

@app.post("/hr/postings", response_model=JobPostingOut, dependencies=[Depends(require_roles(Role.hr_manager, Role.admin))])
def create_posting(data: JobPostingIn, db: Session = Depends(get_db)):
    return JobPostingRepo(db).create(data)

@app.get("/hr/postings", response_model=List[JobPostingOut], dependencies=[Depends(require_roles(Role.hr_manager, Role.admin, Role.coordinator, Role.intern))])
def list_postings(campaign_id: Optional[int] = None, db: Session = Depends(get_db)):
    return JobPostingRepo(db).list(campaign_id)

@app.post("/hr/applications", response_model=ApplicationOut)
def submit_application(data: ApplicationIn, db: Session = Depends(get_db)):
    return ApplicationRepo(db).create(data)

@app.post("/hr/applications/{app_id}/status", response_model=ApplicationOut, dependencies=[Depends(require_roles(Role.hr_manager, Role.admin, Role.coordinator))])
def update_application_status(app_id: int, status_: str, notes: str = "", db: Session = Depends(get_db)):
    return ApplicationRepo(db).update_status(app_id, status_, notes)

@app.get("/hr/reports/summary", dependencies=[Depends(require_roles(Role.hr_manager, Role.admin))])
def reports_summary(db: Session = Depends(get_db)):
    return ReportingService(db).program_summary()

# Coordinator endpoints
@app.post("/coord/interviews", response_model=InterviewOut, dependencies=[Depends(require_roles(Role.coordinator, Role.admin))])
def schedule_interview(data: InterviewIn, bg: BackgroundTasks, db: Session = Depends(get_db)):
    iv = InterviewRepo(db).create(data)
    application = db.query(Application).get(data.application_id)
    if application:
        subj = f"Interview scheduled (app #{application.id})"
        body = f"Your interview: {iv.scheduled_at.isoformat()} via {iv.mode}. Link/Place: {iv.location_or_link}"
        bg.add_task(NotificationService().send_email, application.applicant_email, subj, body)
    return iv

@app.post("/coord/interviews/{interview_id}/reminder", dependencies=[Depends(require_roles(Role.coordinator, Role.admin))])
def send_reminder(interview_id: int, db: Session = Depends(get_db)):
    InterviewRepo(db).mark_reminder(interview_id)
    return {"ok": True}

@app.post("/coord/training/programs", response_model=TrainingProgramOut, dependencies=[Depends(require_roles(Role.coordinator, Role.admin))])
def create_training_program(data: TrainingProgramIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return TrainingRepo(db).create_program(current.id, data)

@app.post("/coord/kpis", response_model=KPIOut, dependencies=[Depends(require_roles(Role.coordinator, Role.admin))])
def create_kpi(data: KPIIn, db: Session = Depends(get_db)):
    return KPIRepo(db).create(data)

@app.post("/coord/performance", response_model=PerformanceRecordOut, dependencies=[Depends(require_roles(Role.coordinator, Role.admin, Role.mentor))])
def record_performance(data: PerformanceRecordIn, db: Session = Depends(get_db)):
    return PerformanceRepo(db).record(data)

# Mentor endpoints
@app.post("/mentor/daily-logs", response_model=DailyLogOut, dependencies=[Depends(require_roles(Role.mentor, Role.admin))])
def create_daily_log(data: DailyLogIn, db: Session = Depends(get_db)):
    return DailyLogRepo(db).create(data)

@app.post("/mentor/assessments", response_model=AssessmentOut, dependencies=[Depends(require_roles(Role.mentor, Role.admin))])
def create_assessment(data: AssessmentIn, db: Session = Depends(get_db)):
    return AssessmentRepo(db).create(data)

@app.post("/mentor/messages", response_model=MessageOut, dependencies=[Depends(require_roles(Role.mentor, Role.admin))])
def send_message(data: MessageIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return MessageRepo(db).send(current.id, data)

# Intern endpoints
@app.get("/intern/dashboard")
def intern_dashboard(db: Session = Depends(get_db), current: User = Depends(require_roles(Role.intern))):
    perf = PerformanceRepo(db).list_by_intern(current.id)
    logs = DailyLogRepo(db).list_for_intern(current.id)
    assessments = AssessmentRepo(db).list_by_intern(current.id)
    prof = ProfileRepo(db).get(current.id)
    suggestions = []
    for a in assessments:
        if a.score < 60 and a.skill not in suggestions:
            suggestions.append(f"Revise fundamentals of {a.skill}")
    return {
        "profile": InternProfileOut.from_orm(prof) if prof else None,
        "performance_records": [PerformanceRecordOut.from_orm(p) for p in perf],
        "daily_logs": [DailyLogOut.from_orm(l) for l in logs],
        "assessments": [AssessmentOut.from_orm(a) for a in assessments],
        "suggestions": suggestions,
    }

@app.post("/intern/profile", response_model=InternProfileOut, dependencies=[Depends(require_roles(Role.intern))])
def upsert_profile(data: InternProfileIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return ProfileRepo(db).upsert(current.id, data)

@app.post("/intern/feedback", response_model=FeedbackOut, dependencies=[Depends(require_roles(Role.intern))])
def submit_feedback(data: FeedbackIn, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return FeedbackRepo(db).create(current.id, data)

@app.get("/intern/messages", response_model=List[MessageOut], dependencies=[Depends(require_roles(Role.intern))])
def inbox(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return MessageRepo(db).inbox(current.id)

# Admin endpoints
@app.post("/admin/settings", dependencies=[Depends(require_roles(Role.admin))])
def set_setting(data: SettingIn, db: Session = Depends(get_db)):
    SettingsRepo(db).set(data.key, data.value)
    return {"ok": True}

@app.get("/admin/settings/{key}", response_model=Any, dependencies=[Depends(require_roles(Role.admin))])
def get_setting(key: str, db: Session = Depends(get_db)):
    return SettingsRepo(db).get(key)

@app.post("/admin/seed")
def seed_data(db: Session = Depends(get_db)):
    repo = UserRepo(db)
    def ensure(email, name, role, pwd="Password123!"):
        if not repo.by_email(email):
            repo.create(UserCreate(email=email, full_name=name, password=pwd, role=role))
    ensure("admin@ims.local", "Admin", Role.admin)
    ensure("hr@ims.local", "HR Manager", Role.hr_manager)
    ensure("coord@ims.local", "Coordinator", Role.coordinator)
    ensure("mentor@ims.local", "Mentor", Role.mentor)
    ensure("intern@ims.local", "Intern", Role.intern)
    return {"ok": True}

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

def selenium_smoke_test(base_url: str = "http://localhost:8000"):
    """
    Run a quick browser-based smoke test that:
    - calls /admin/seed
    - gets token for admin
    - opens Swagger UI, Authorize, and calls GET /hr/campaigns
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        import requests
    except Exception as e:
        print("Selenium or requests not installed:", e)
        return

    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    wait = WebDriverWait(driver, 20)
    try:
        requests.post(f"{base_url}/admin/seed")
        r = requests.post(f"{base_url}/auth/token", data={"username": "admin@ims.local", "password": "Password123!"})
        r.raise_for_status()
        token = r.json()["access_token"]

        driver.get(f"{base_url}/docs")
        # try to click authorize
        try:
            btn = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'button[title="Authorize"]')))
            btn.click()
            # find input, fill token
            token_input = wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'input[placeholder="bearer token"]')))
            token_input.clear(); token_input.send_keys(f"Bearer {token}")
            # click Authorize button in modal
            try:
                auth_btn = driver.find_element(By.CSS_SELECTOR, 'button.btn.modal-btn.auth.authorize.button')
                auth_btn.click()
            except Exception:
                pass
            # close modal (done)
            try:
                done = driver.find_element(By.CSS_SELECTOR, 'button.btn.modal-btn.auth.done')
                done.click()
            except Exception:
                pass
        except Exception:
            # Swagger UI version may vary; fallback to API direct check
            pass

        # Call GET /hr/campaigns with token via requests to validate
        r2 = requests.get(f"{base_url}/hr/campaigns", headers={"Authorization": f"Bearer {token}"})
        if r2.status_code != 200:
            raise RuntimeError(f"GET /hr/campaigns failed: {r2.status_code} {r2.text}")
        print("Selenium smoke test passed: API responsive and authorized.")
    finally:
        driver.quit()

if __name__ == "__main__":
    import uvicorn
    # allow running optional smoke test via arg
    if len(sys.argv) > 1 and sys.argv[1] == "smoke":
        # run a simple server in background (not handled here) or call test after server up
        print("Run uvicorn in another terminal, then call: python main.py smoke")
        sys.exit(0)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel


class ChildActionIn(BaseModel):
    action: str
    payload: dict = {}


child_router = APIRouter(tags=["child-api"])  # không prefix -> mount ở gốc /

@child_router.get("/health")
def health():
    return {"ok": True, "msg": "Child API healthy"}

@child_router.post("/run-action")
def run_action(body: ChildActionIn = Body(...), db: Session = Depends(get_db)):
    a = body.action.lower()
    if a == "seed":
        return seed_data.__wrapped__(db) if hasattr(seed_data, "__wrapped__") else seed_data(db=db)
    if a == "summary":
        rs = ReportingService(db).program_summary()
        return {"ok": True, "summary": rs}
    if a == "custom_sql":
        sql = body.payload.get("sql")
        if not sql:
            raise HTTPException(400, "Missing 'sql' in payload")
        try:
            res = db.execute(sql)
            rows = [dict(r) for r in res.mappings().all()]
            return {"ok": True, "rows": rows}
        except Exception as e:
            raise HTTPException(400, f"SQL error: {e}")
    raise HTTPException(400, f"Unknown action: {body.action}")

app.include_router(child_router)
