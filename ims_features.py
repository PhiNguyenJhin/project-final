"""
ims_features.py
Bổ sung: JobCampaign, Applications, Interview scheduling, KPI/Performance, DailyLog, Messaging, Reporting, Dashboards.

Hướng dẫn tích hợp (trong main.py sau khi tạo app và models):
from ims_features import init_features
init_features(app, imports_from_main={
    'get_db': get_db,
    'require_roles': require_roles,
    'get_current_user': get_current_user,
    'NotificationService': NotificationService,   # nếu bạn có
})
"""
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
import json
import datetime

# Try import from main (if present), otherwise these will be injected in init_features()
try:
    from main import get_db, require_roles, get_current_user, NotificationService
    from main import InternshipCampaign, JobPosting, Application, Interview, TrainingProgram, KPI, PerformanceRecord, DailyLog, Message, Feedback
except Exception:
    get_db = None
    require_roles = None
    get_current_user = None
    NotificationService = None
    InternshipCampaign = None
    JobPosting = None
    Application = None
    Interview = None
    TrainingProgram = None
    KPI = None
    PerformanceRecord = None
    DailyLog = None
    Message = None
    Feedback = None

# ---------------- SCHEMAS ----------------
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
    scheduled_at: datetime.datetime
    mode: str = "online"
    location_or_link: Optional[str] = None

class KPIIn(BaseModel):
    name: str
    description: Optional[str] = None
    weight: float = 1.0

class PerformanceIn(BaseModel):
    intern_id: int
    kpi_id: int
    value: float

class DailyLogIn(BaseModel):
    intern_id: int
    mentor_id: int
    activities: str
    date: Optional[datetime.date] = None
    mentor_feedback: Optional[str] = ""

class MessageIn(BaseModel):
    receiver_id: int
    content: str

# ---------------- REPOSITORY-LIKE HELPERS ----------------
def _json_dumps_safe(v):
    try:
        return json.dumps(v)
    except Exception:
        return json.dumps(str(v))

# ---------------- ROUTERS ----------------
jobs_router = APIRouter(prefix="/jobs", tags=["jobs"])
interview_router = APIRouter(prefix="/interviews", tags=["interviews"])
kpi_router = APIRouter(prefix="/kpis", tags=["kpis"])
mentor_router = APIRouter(prefix="/mentor-tools", tags=["mentor-tools"])
report_router = APIRouter(prefix="/reports", tags=["reports"])
dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# ----- Job postings & applications -----
@jobs_router.post("/postings", response_model=JobPostingOut)
def create_posting(payload: JobPostingIn, db: Session = Depends(lambda: get_db()),
                   current = Depends(lambda: require_roles(["hr_manager", "admin"])( ))):
    # current dependency wrapper: init_features will inject real require_roles/get_db
    # create new posting
    if JobPosting is None:
        raise HTTPException(500, "JobPosting model not available")
    jp = JobPosting(campaign_id=payload.campaign_id, title=payload.title,
                    description=payload.description, location=payload.location,
                    skills_required=_json_dumps_safe(payload.skills_required), slots=payload.slots)
    db.add(jp); db.commit(); db.refresh(jp)
    return jp

@jobs_router.get("/postings", response_model=List[JobPostingOut])
def list_postings(campaign_id: Optional[int] = None, db: Session = Depends(lambda: get_db()),
                  current = Depends(lambda: require_roles(["hr_manager","admin","coordinator","intern"])( ))):
    if JobPosting is None:
        raise HTTPException(500, "JobPosting model not available")
    q = db.query(JobPosting)
    if campaign_id:
        q = q.filter(JobPosting.campaign_id == campaign_id)
    return q.all()

@jobs_router.post("/applications", response_model=ApplicationOut)
def submit_application(payload: ApplicationIn, db: Session = Depends(lambda: get_db())):
    if Application is None:
        raise HTTPException(500, "Application model not available")
    appn = Application(posting_id=payload.posting_id, applicant_email=str(payload.applicant_email), cv_url=payload.cv_url)
    db.add(appn); db.commit(); db.refresh(appn)
    return appn

@jobs_router.post("/applications/{app_id}/status", response_model=ApplicationOut)
def update_application_status(app_id: int, status: str, notes: str = "", db: Session = Depends(lambda: get_db()),
                              current = Depends(lambda: require_roles(["hr_manager","admin","coordinator"])( ))):
    a = db.query(Application).get(app_id)
    if not a: raise HTTPException(404, "Application not found")
    a.status = status; a.notes = notes
    db.commit(); db.refresh(a)
    return a

# ----- Interview scheduling -----
@interview_router.post("/", response_model=dict)
def schedule_interview(payload: InterviewIn, background: BackgroundTasks, db: Session = Depends(lambda: get_db()),
                       current = Depends(lambda: require_roles(["coordinator","admin"])( ))):
    if Interview is None or Application is None:
        raise HTTPException(500, "Interview/Application model not available")
    iv = Interview(application_id=payload.application_id, interviewer_id=payload.interviewer_id,
                   scheduled_at=payload.scheduled_at, mode=payload.mode, location_or_link=payload.location_or_link)
    db.add(iv); db.commit(); db.refresh(iv)
    # send reminder (mock) via background
    appl = db.query(Application).get(payload.application_id)
    if appl:
        subj = f"Interview scheduled for application #{appl.id}"
        body = f"Your interview at {payload.scheduled_at.isoformat()} via {payload.mode}. Link: {payload.location_or_link}"
        if NotificationService:
            background.add_task(NotificationService().send_email, appl.applicant_email, subj, body)
        else:
            background.add_task(lambda: print(f"[MOCK EMAIL] to={appl.applicant_email} subj={subj}"))
    return {"ok": True, "id": iv.id}

@interview_router.post("/{interview_id}/reminder")
def send_interview_reminder(interview_id: int, db: Session = Depends(lambda: get_db()),
                            current = Depends(lambda: require_roles(["coordinator","admin"])( ))):
    iv = db.query(Interview).get(interview_id)
    if not iv: raise HTTPException(404, "Interview not found")
    iv.reminder_sent = True
    db.commit()
    return {"ok": True}

# ----- KPI & Performance -----
@kpi_router.post("/", response_model=dict, dependencies=[Depends(lambda: require_roles(["coordinator","admin"])( ))])
def create_kpi(payload: KPIIn, db: Session = Depends(lambda: get_db())):
    if KPI is None:
        raise HTTPException(500, "KPI model not available")
    k = KPI(name=payload.name, description=payload.description, weight=payload.weight)
    db.add(k); db.commit(); db.refresh(k)
    return {"ok": True, "id": k.id}

@kpi_router.get("/", response_model=List[Dict[str,Any]])
def list_kpis(db: Session = Depends(lambda: get_db()), current = Depends(lambda: require_roles(["coordinator","admin","mentor","intern"])( ))):
    if KPI is None:
        raise HTTPException(500, "KPI model not available")
    items = db.query(KPI).all()
    return [{"id": k.id, "name": k.name, "description": k.description, "weight": k.weight} for k in items]

@kpi_router.post("/record", response_model=dict, dependencies=[Depends(lambda: require_roles(["coordinator","admin","mentor"])( ))])
def record_performance(payload: PerformanceIn, db: Session = Depends(lambda: get_db())):
    if PerformanceRecord is None:
        raise HTTPException(500, "PerformanceRecord model not available")
    pr = PerformanceRecord(intern_id=payload.intern_id, kpi_id=payload.kpi_id, value=payload.value)
    db.add(pr); db.commit(); db.refresh(pr)
    return {"ok": True, "id": pr.id}

@kpi_router.get("/intern/{intern_id}", response_model=List[Dict[str,Any]])
def get_intern_performance(intern_id: int, db: Session = Depends(lambda: get_db()), current = Depends(lambda: require_roles(["coordinator","admin","mentor","intern"])( ))):
    recs = db.query(PerformanceRecord).filter(PerformanceRecord.intern_id == intern_id).all()
    return [{"kpi_id": r.kpi_id, "value": r.value, "recorded_at": r.recorded_at.isoformat()} for r in recs]

# ----- Mentor tools: daily logs & messaging -----
@mentor_router.post("/daily-log", response_model=dict, dependencies=[Depends(lambda: require_roles(["mentor","admin"])( ))])
def create_daily_log(payload: DailyLogIn, db: Session = Depends(lambda: get_db())):
    if DailyLog is None:
        raise HTTPException(500, "DailyLog model not available")
    d = DailyLog(intern_id=payload.intern_id, mentor_id=payload.mentor_id, activities=payload.activities, date=payload.date or datetime.date.today(), mentor_feedback=payload.mentor_feedback)
    db.add(d); db.commit(); db.refresh(d)
    return {"ok": True, "id": d.id}

@mentor_router.post("/message", response_model=dict, dependencies=[Depends(lambda: require_roles(["mentor","admin"])( ))])
def send_message(payload: MessageIn, db: Session = Depends(lambda: get_db()), current_user = Depends(lambda: get_current_user())):
    if Message is None:
        raise HTTPException(500, "Message model not available")
    m = Message(sender_id=current_user.id, receiver_id=payload.receiver_id, content=payload.content)
    db.add(m); db.commit(); db.refresh(m)
    return {"ok": True, "id": m.id}

@mentor_router.get("/inbox", response_model=List[Dict[str,Any]], dependencies=[Depends(lambda: require_roles(["mentor","intern","admin"])( ))])
def inbox(db: Session = Depends(lambda: get_db()), current_user = Depends(lambda: get_current_user())):
    msgs = db.query(Message).filter(Message.receiver_id == current_user.id).order_by(Message.sent_at.desc()).all()
    return [{"id": m.id, "from": m.sender_id, "content": m.content, "sent_at": m.sent_at.isoformat()} for m in msgs]

# ----- Reporting & Dashboard -----
@report_router.get("/summary", dependencies=[Depends(lambda: require_roles(["hr_manager","admin"])( ))])
def summary_report(db: Session = Depends(lambda: get_db())):
    # basic metrics
    user_counts = {}
    try:
        from sqlalchemy import func
        # count interns
        intern_count = db.query(func.count()).select_from(InternshipCampaign.__table__ )  # placeholder to ensure model exists
    except Exception:
        pass
    # construct report using available models
    total_interns = db.query(PerformanceRecord).with_entities().count() if PerformanceRecord is not None else 0
    total_applications = db.query(Application).count() if Application is not None else 0
    total_campaigns = db.query(InternshipCampaign).count() if InternshipCampaign is not None else 0
    # avg performance by intern
    perf = db.query(PerformanceRecord).all() if PerformanceRecord is not None else []
    totals, counts = {}, {}
    for p in perf:
        totals[p.intern_id] = totals.get(p.intern_id, 0.0) + p.value
        counts[p.intern_id] = counts.get(p.intern_id, 0) + 1
    averages = {iid: (totals[iid]/counts[iid]) for iid in totals} if totals else {}
    return {
        "campaigns": total_campaigns,
        "applications": total_applications,
        "avg_performance_by_intern": averages,
    }

@dashboard_router.get("/intern", dependencies=[Depends(lambda: require_roles(["intern"])( ))])
def intern_dashboard(db: Session = Depends(lambda: get_db()), current_user = Depends(lambda: get_current_user())):
    # assemble profile, performance, logs, assessments, suggestions
    prof = None
    try:
        prof = db.query(InternshipCampaign).first()  # placeholder: actual profile model should be used
    except Exception:
        prof = None
    perf = []
    if PerformanceRecord is not None:
        perf = db.query(PerformanceRecord).filter(PerformanceRecord.intern_id == current_user.id).all()
    logs = db.query(DailyLog).filter(DailyLog.intern_id == current_user.id).all() if DailyLog is not None else []
    assessments = db.query(Feedback).filter(Feedback.intern_id == current_user.id).all() if Feedback is not None else []
    suggestions = []
    for a in assessments:
        if hasattr(a, 'content') and isinstance(a.content, str) and len(a.content) < 50:
            suggestions.append("Consider improving: " + a.content)
    return {
        "profile": None,
        "performance": [{"kpi_id": p.kpi_id, "value": p.value} for p in perf],
        "logs": [{"activities": l.activities, "date": str(l.date)} for l in logs],
        "assessments": [{"notes": f.content} for f in assessments] if assessments else [],
        "suggestions": suggestions
    }

# --------------- Integration ----------------
def init_features(app, imports_from_main: dict = None):
    """
    Gọi trong main.py sau khi app, models, dependencies đã sẵn sàng.
    Ví dụ:
      from ims_features import init_features
      init_features(app, imports_from_main={
          'get_db': get_db,
          'require_roles': require_roles,
          'get_current_user': get_current_user,
          'NotificationService': NotificationService,
          # models not necessary if in main importable
      })
    """
    global get_db, require_roles, get_current_user, NotificationService
    global InternshipCampaign, JobPosting, Application, Interview, TrainingProgram, KPI, PerformanceRecord, DailyLog, Message, Feedback
    if imports_from_main:
        for k, v in imports_from_main.items():
            globals()[k] = v

    # sanity checks
    if get_db is None or require_roles is None or get_current_user is None:
        raise RuntimeError("Please inject get_db, require_roles and get_current_user via imports_from_main")

    # include routers
    app.include_router(jobs_router)
    app.include_router(interview_router)
    app.include_router(kpi_router)
    app.include_router(mentor_router)
    app.include_router(report_router)
    app.include_router(dashboard_router)
