# ims_app.py
"""
Intern Management System (IMS) - Fixed template handling for /login
- Use templates/ directory for login.html if present
- If template missing, return inline HTML (avoids 500)
- Other features: JWT, SQLite/SQLServer via .env, bootstrap admin, selenium demo, migration
"""

from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Form, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import enum, os, hashlib, jwt, traceback

load_dotenv()
DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
SQLITE_URL = "sqlite:///./ims_demo.db"
SQLSERVER_URL = os.getenv("SQLSERVER_URL", "")

JWT_SECRET = os.getenv("JWT_SECRET", "replace-with-a-strong-secret-in-prod")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

Base = declarative_base()
if DB_TYPE == "sqlserver" and SQLSERVER_URL:
    engine = create_engine(SQLSERVER_URL)
else:
    engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class RoleEnum(str, enum.Enum):
    admin = "admin"
    hr = "hr"
    coordinator = "coordinator"
    mentor = "mentor"
    intern = "intern"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    role = Column(Enum(RoleEnum))
    email = Column(String, unique=True, nullable=True)

Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return get_password_hash(plain_password) == hashed_password

def create_access_token(data: dict):
    payload = data.copy()
    payload.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

app = FastAPI(title=f"IMS ({DB_TYPE.upper()})")

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)  # safe even if folder missing

class TokenOut(BaseModel):
    access_token: str
    token_type: str

@app.post("/token", response_model=TokenOut)
def login_for_token(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    try:
        login_path = os.path.join(TEMPLATES_DIR, "login.html")
        if os.path.exists(login_path):
            return templates.TemplateResponse("login.html", {"request": request})
        html = """
        <!doctype html>
        <html>
          <head><meta charset="utf-8"><title>IMS Login</title></head>
          <body>
            <h2>IMS Login (fallback)</h2>
            <form method="post" action="/login">
              <label>Username: <input type="text" name="username" required></label><br><br>
              <label>Password: <input type="password" name="password" required></label><br><br>
              <button type="submit">Login</button>
            </form>
            <p><em>Note: Put a login.html into ./templates/ to use the template version.</em></p>
          </body>
        </html>
        """
        return HTMLResponse(content=html, status_code=200)
    except Exception as e:
        traceback.print_exc()
        return PlainTextResponse("Error rendering login page", status_code=500)

@app.post("/login", response_class=HTMLResponse)
def handle_login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.hashed_password):
            return HTMLResponse("<h3 style='color:red'>Sai tên đăng nhập hoặc mật khẩu</h3>", status_code=401)
        token = create_access_token({"sub": user.username})
        return HTMLResponse(f"""
            <h3>Đăng nhập thành công</h3>
            <p>Username: {user.username} (role: {user.role})</p>
            <p>JWT token:</p>
            <textarea cols="100" rows="5">{token}</textarea>
            <p>Swagger: <a href="/docs">/docs</a></p>
        """)
    except Exception:
        traceback.print_exc()
        return HTMLResponse("Server error during login", status_code=500)

@app.get("/scrape-candidates")
def scrape_candidates():
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        try:
            driver.get("https://httpbin.org/html")
            title = driver.find_element(By.TAG_NAME, "h1").text
            return {"status": "success", "page_title": title}
        finally:
            driver.quit()
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Selenium error: {str(e)}")

@app.post("/users")
def create_user(username: str = Form(...), password: str = Form(...), full_name: str = Form(""), email: str = Form(""), db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    if current.role != RoleEnum.admin:
        raise HTTPException(status_code=403, detail="Permission denied")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username exists")
    user = User(username=username, hashed_password=get_password_hash(password), full_name=full_name, role=RoleEnum.intern, email=email)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username}

from sqlalchemy.orm import sessionmaker

def migrate_between_dbs(src_url, dst_url):
    src_engine = create_engine(src_url, connect_args={"check_same_thread": False}) if src_url.startswith("sqlite") else create_engine(src_url)
    dst_engine = create_engine(dst_url, connect_args={"check_same_thread": False}) if dst_url.startswith("sqlite") else create_engine(dst_url)
    SrcSession = sessionmaker(bind=src_engine)
    DstSession = sessionmaker(bind=dst_engine)
    Base.metadata.create_all(bind=dst_engine)
    s = SrcSession(); d = DstSession()
    try:
        for model in [User]:
            for row in s.query(model).all():
                new_obj = model(**{c.name: getattr(row, c.name) for c in model.__table__.columns})
                d.merge(new_obj)
        d.commit()
    finally:
        s.close(); d.close()

@app.post("/migrate-to-sqlserver")
def migrate_to_sqlserver():
    if not os.path.exists("ims_demo.db"):
        raise HTTPException(status_code=404, detail="SQLite DB not found")
    if not SQLSERVER_URL:
        raise HTTPException(status_code=400, detail="SQLSERVER_URL not configured in .env")
    migrate_between_dbs(SQLITE_URL, SQLSERVER_URL)
    return {"status": "ok", "detail": "migrated sqlite -> sqlserver"}

@app.post("/migrate-to-sqlite")
def migrate_to_sqlite():
    if not SQLSERVER_URL:
        raise HTTPException(status_code=400, detail="SQLSERVER_URL not configured in .env")
    migrate_between_dbs(SQLSERVER_URL, SQLITE_URL)
    return {"status": "ok", "detail": "migrated sqlserver -> sqlite"}

def bootstrap_admin():
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.role == RoleEnum.admin).first()
        if not existing:
            admin = User(
                username="admin",
                hashed_password=get_password_hash("admin123"),
                full_name="System Administrator",
                role=RoleEnum.admin,
                email="admin@example.com"
            )
            db.add(admin)
            db.commit()
            print("✅ Created default admin: admin / admin123")
        else:
            print("ℹ️ Default admin exists.")
    except Exception:
        traceback.print_exc()
    finally:
        db.close()

bootstrap_admin()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ims_app:app", host="127.0.0.1", port=8000, reload=True)
