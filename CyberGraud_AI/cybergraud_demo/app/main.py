from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from .db import connect, get_user, get_user_by_email, init_db, public_user, hash_password, verify_password
from .model import FEATURES, MODEL_ACCURACY, predict, retrain, simulate_features

SECRET = os.getenv("JWT_SECRET", "cybergraud-final-demo-secret-change-me")
BASE = Path(__file__).resolve().parent
app = FastAPI(title="CyberGraud AI", version="2.0.0")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

ROLES = ["Student", "Website Owner", "Admin"]
ATTACKS = ["Normal", "SQL Injection", "XSS", "Brute Force", "DDoS"]

@app.on_event("startup")
def startup(): init_db()

class LoginBody(BaseModel):
    email: str
    password: str


class RegisterBody(BaseModel):
    name: str = Field(min_length=2)
    email: str
    password: str = Field(min_length=8)
    role: str = "Student"
class SimBody(BaseModel):
    attack_type: str; mode: str = "Gamified"; source: str = "Demo User"; target: str = "Sandbox Application"
    features: dict[str,float] | None = None
class PasswordBody(BaseModel): current_password: str; new_password: str = Field(min_length=8)
class KBBody(BaseModel): attack_type: str; description: str; prevention: str; severity: str
class RoleBody(BaseModel): role: str


def token_for(user):
    payload={"sub":str(user["id"]),"role":user["role"],"exp":datetime.now(timezone.utc)+timedelta(hours=8)}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def current_user(request: Request):
    auth=request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): raise HTTPException(401,"Login required")
    try:
        payload=jwt.decode(auth.split(" ",1)[1],SECRET,algorithms=["HS256"])
        user=get_user(int(payload["sub"]))
        if not user or not user["active"]: raise ValueError()
        return user
    except Exception: raise HTTPException(401,"Invalid or expired token")


def admin_only(user):
    if user["role"] != "Admin": raise HTTPException(403,"Admin access required")


def log_action(user_id, action, details=""):
    conn=connect(); conn.execute("INSERT INTO audit_logs(user_id,action,details) VALUES(?,?,?)",(user_id,action,details)); conn.commit(); conn.close()


def recommendations(attack_type):
    data={
        "SQL Injection":["Use parameterized queries / prepared statements","Validate and constrain user input","Apply least-privilege database accounts","Use a WAF and database activity monitoring"],
        "XSS":["Sanitize untrusted input","Use context-aware output encoding","Deploy a Content Security Policy","Use secure HttpOnly/SameSite cookies"],
        "Brute Force":["Enable rate limiting","Use MFA","Add CAPTCHA after repeated failures","Alert on unusual authentication patterns"],
        "DDoS":["Use rate limiting and traffic shaping","Place the application behind a CDN","Use upstream DDoS protection","Monitor request and packet rates"],
        "Normal":["Continue centralized logging","Review security baselines regularly","Keep dependencies patched","Monitor for anomalous changes"]}
    return data.get(attack_type,data["Normal"])


def badges_for(points):
    badges=[]
    if points>=25: badges.append("First Responder")
    if points>=100: badges.append("Threat Hunter")
    if points>=250: badges.append("Cyber Defender")
    return badges

@app.get("/",response_class=HTMLResponse)
def home(request:Request): return templates.TemplateResponse("index.html",{"request":request})

@app.post("/api/register")
def register(body:RegisterBody):
    if body.role not in ["Student","Website Owner"]: raise HTTPException(400,"Invalid registration role")
    conn=connect()
    try:
        cur=conn.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",(body.name.strip(),body.email.lower(),hash_password(body.password),body.role))
        conn.commit(); user=get_user(cur.lastrowid); log_action(user["id"],"REGISTER","Account created")
        return {"token":token_for(user),"user":public_user(user)}
    except Exception: conn.rollback(); raise HTTPException(400,"Email already registered")
    finally: conn.close()

@app.post("/api/login")
def login(body:LoginBody):
    user=get_user_by_email(body.email.lower())
    if not user or not user["active"] or not verify_password(body.password,user["password_hash"]): raise HTTPException(401,"Invalid email or password")
    conn=connect(); conn.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?",(user["id"],)); conn.commit(); conn.close(); log_action(user["id"],"LOGIN","Successful login")
    return {"token":token_for(user),"user":public_user(get_user(user["id"]))}

@app.get("/api/me")
def me(user=Depends(current_user)): return public_user(user)

@app.post("/api/change-password")
def change_password(body:PasswordBody,user=Depends(current_user)):
    if not verify_password(body.current_password,user["password_hash"]): raise HTTPException(400,"Current password is incorrect")
    conn=connect(); conn.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(body.new_password),user["id"])); conn.commit(); conn.close(); log_action(user["id"],"PASSWORD_CHANGED","Password updated")
    return {"message":"Password changed successfully"}

@app.get("/api/dashboard")
def dashboard(user=Depends(current_user)):
    conn=connect()
    total=conn.execute("SELECT COUNT(*) FROM events WHERE user_id=?",(user["id"],)).fetchone()[0]
    high=conn.execute("SELECT COUNT(*) FROM events WHERE user_id=? AND risk='High'",(user["id"],)).fetchone()[0]
    malicious=conn.execute("SELECT COUNT(*) FROM events WHERE user_id=? AND prediction='Malicious'",(user["id"],)).fetchone()[0]
    by=conn.execute("SELECT attack_type,COUNT(*) c FROM events WHERE user_id=? GROUP BY attack_type ORDER BY c DESC",(user["id"],)).fetchall()
    timeline=conn.execute("SELECT substr(created_at,1,10) day,COUNT(*) c FROM events WHERE user_id=? GROUP BY day ORDER BY day DESC LIMIT 14",(user["id"],)).fetchall()
    recent=conn.execute("SELECT id,mode,source,target,attack_type,prediction,risk,confidence,created_at FROM events WHERE user_id=? ORDER BY id DESC LIMIT 8",(user["id"],)).fetchall()
    board=conn.execute("SELECT name,role,points FROM users WHERE active=1 ORDER BY points DESC,id LIMIT 10").fetchall()
    threat_map=conn.execute("SELECT source,COUNT(*) c FROM events WHERE user_id=? GROUP BY source ORDER BY c DESC LIMIT 6",(user["id"],)).fetchall()
    conn.close()
    badges=badges_for(user["points"])
    return {"user":public_user(user),"stats":{"total":total,"high":high,"malicious":malicious,"points":user["points"],"badges":badges},"by_attack":[dict(r) for r in by],"timeline":[dict(r) for r in timeline][::-1],"recent":[dict(r) for r in recent],"leaderboard":[dict(r) for r in board],"threat_map":[dict(r) for r in threat_map]}

@app.post("/api/simulate")
def simulate(body:SimBody,user=Depends(current_user)):
    if body.attack_type not in ATTACKS: raise HTTPException(400,"Unsupported scenario")
    features=body.features if body.features else simulate_features(body.attack_type.lower().replace(" ","_"))
    for f in FEATURES:
        if f not in features: raise HTTPException(400,f"Missing feature: {f}")
    result=predict(features); recs=recommendations(result["attack_type"])
    points={"Low":10,"Medium":20,"High":30}[result["risk"]] if result["prediction"]=="Malicious" else 5
    conn=connect(); cur=conn.execute("""INSERT INTO events(user_id,mode,source,target,attack_type,prediction,risk,confidence,malicious_probability,features_json,explanation_json,recommendations_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",(user["id"],body.mode,body.source,body.target,result["attack_type"],result["prediction"],result["risk"],result["confidence"],result["malicious_probability"],json.dumps(features),json.dumps(result["explanation"]),json.dumps(recs)))
    new_points=user["points"]+points; conn.execute("UPDATE users SET points=?,badges_json=? WHERE id=?",(new_points,json.dumps(badges_for(new_points)),user["id"])); conn.commit(); conn.close(); log_action(user["id"],"SIMULATION",f"{body.mode}: {result['attack_type']} / {result['risk']}")
    return {**result,"features":features,"recommendations":recs,"points_earned":points,"event_id":cur.lastrowid,"timestamp":datetime.now().isoformat()}

@app.get("/api/events")
def events(user=Depends(current_user)):
    conn=connect(); rows=conn.execute("SELECT e.*,u.email FROM events e JOIN users u ON u.id=e.user_id WHERE e.user_id=? ORDER BY e.id DESC",(user["id"],)).fetchall(); conn.close()
    return [{**dict(r),"features":json.loads(r["features_json"]),"explanation":json.loads(r["explanation_json"]),"recommendations":json.loads(r["recommendations_json"])} for r in rows]

@app.get("/api/knowledge")
def knowledge(user=Depends(current_user)):
    conn=connect(); rows=conn.execute("SELECT * FROM knowledge_base ORDER BY id").fetchall(); conn.close(); return [dict(r) for r in rows]

@app.get("/api/admin/overview")
def admin_overview(user=Depends(current_user)):
    admin_only(user); conn=connect()
    users=conn.execute("SELECT id,name,email,role,points,active,created_at,last_login FROM users ORDER BY id DESC").fetchall()
    logs=conn.execute("SELECT e.id,u.email,e.mode,e.source,e.target,e.attack_type,e.prediction,e.risk,e.confidence,e.created_at FROM events e JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 100").fetchall()
    audit=conn.execute("SELECT a.id,COALESCE(u.email,'system') email,a.action,a.details,a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100").fetchall()
    m=conn.execute("SELECT * FROM model_runs ORDER BY id DESC LIMIT 1").fetchone(); conn.close()
    from .model import MODEL_ACCURACY
    model_info=dict(m) if m else {"algorithm":"Random Forest","samples":1750,"accuracy":MODEL_ACCURACY}
    return {"users":[dict(x) for x in users],"logs":[dict(x) for x in logs],"audit":[dict(x) for x in audit],"model":model_info}

@app.patch("/api/admin/users/{user_id}/role")
def change_role(user_id:int,body:RoleBody,user=Depends(current_user)):
    admin_only(user)
    if body.role not in ROLES: raise HTTPException(400,"Invalid role")
    conn=connect(); target=conn.execute("SELECT * FROM users WHERE id=?",(user_id,)).fetchone()
    if not target: conn.close(); raise HTTPException(404,"User not found")
    if target["id"]==user["id"] and body.role!="Admin": conn.close(); raise HTTPException(400,"Admin cannot remove their own admin role")
    conn.execute("UPDATE users SET role=? WHERE id=?",(body.role,user_id)); conn.commit(); conn.close(); log_action(user["id"],"ROLE_CHANGED",f"User {user_id} -> {body.role}")
    return {"message":"Role updated"}

@app.patch("/api/admin/users/{user_id}/status")
def change_status(user_id:int,user=Depends(current_user)):
    admin_only(user)
    if user_id==user["id"]: raise HTTPException(400,"You cannot disable your own account")
    conn=connect(); row=conn.execute("SELECT active FROM users WHERE id=?",(user_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404,"User not found")
    new=0 if row["active"] else 1; conn.execute("UPDATE users SET active=? WHERE id=?",(new,user_id)); conn.commit(); conn.close(); log_action(user["id"],"USER_STATUS",f"User {user_id} active={new}")
    return {"active":new}

@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id:int,user=Depends(current_user)):
    admin_only(user)
    if user_id==user["id"]: raise HTTPException(400,"You cannot delete your own account")
    conn=connect(); conn.execute("DELETE FROM users WHERE id=?",(user_id,)); conn.commit(); conn.close(); log_action(user["id"],"USER_DELETED",f"User {user_id}")
    return {"message":"User deleted"}

@app.post("/api/admin/knowledge")
def add_kb(body:KBBody,user=Depends(current_user)):
    admin_only(user); conn=connect()
    try: conn.execute("INSERT INTO knowledge_base(attack_type,description,prevention,severity) VALUES(?,?,?,?)",(body.attack_type,body.description,body.prevention,body.severity)); conn.commit()
    except Exception: conn.rollback(); raise HTTPException(400,"Attack type already exists")
    finally: conn.close()
    log_action(user["id"],"KB_ADDED",body.attack_type); return {"message":"Knowledge base entry added"}

@app.put("/api/admin/knowledge/{kb_id}")
def update_kb(kb_id:int,body:KBBody,user=Depends(current_user)):
    admin_only(user); conn=connect(); cur=conn.execute("UPDATE knowledge_base SET attack_type=?,description=?,prevention=?,severity=? WHERE id=?",(body.attack_type,body.description,body.prevention,body.severity,kb_id)); conn.commit(); conn.close()
    if cur.rowcount==0: raise HTTPException(404,"Entry not found")
    log_action(user["id"],"KB_UPDATED",str(kb_id)); return {"message":"Knowledge base updated"}

@app.delete("/api/admin/knowledge/{kb_id}")
def delete_kb(kb_id:int,user=Depends(current_user)):
    admin_only(user); conn=connect(); cur=conn.execute("DELETE FROM knowledge_base WHERE id=?",(kb_id,)); conn.commit(); conn.close()
    if cur.rowcount==0: raise HTTPException(404,"Entry not found")
    log_action(user["id"],"KB_DELETED",str(kb_id)); return {"message":"Knowledge base entry deleted"}

@app.post("/api/admin/retrain")
def admin_retrain(user=Depends(current_user)):
    admin_only(user); result=retrain(); conn=connect(); conn.execute("INSERT INTO model_runs(algorithm,samples,accuracy,trained_by) VALUES(?,?,?,?)",(result["algorithm"],result["samples"],result["accuracy"],user["id"])); conn.commit(); conn.close(); log_action(user["id"],"MODEL_RETRAINED",json.dumps(result)); return result

@app.get("/api/report/{event_id}")
def report(event_id:int,user=Depends(current_user)):
    conn=connect(); row=conn.execute("SELECT * FROM events WHERE id=? AND (user_id=? OR ?='Admin')",(event_id,user["id"],user["role"])).fetchone(); conn.close()
    if not row: raise HTTPException(404,"Event not found")
    e=dict(row); explanation=json.loads(e["explanation_json"]); recs=json.loads(e["recommendations_json"]); features=json.loads(e["features_json"])
    buf=io.BytesIO(); c=canvas.Canvas(buf,pagesize=A4); w,h=A4; y=h-45
    def line(text,size=10,bold=False):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica",size); c.drawString(45,y,str(text)[:105]); y-=16
        if y<55: c.showPage(); y=h-45
    line("CyberGraud AI — Security Assessment Report",18,True); y-=8
    for k in ["id","created_at","mode","source","target","attack_type","prediction","risk","confidence","malicious_probability"]: line(f"{k.replace('_',' ').title()}: {e[k]}")
    y-=5; line("Telemetry / Data Collection",12,True)
    for k,v in features.items(): line(f"• {k}: {v}")
    y-=5; line("XAI Explanation",12,True)
    for x in explanation: line(f"• {x['feature']}: {x['value']} — influence {x['influence']} ({x['direction']})")
    y-=5; line("Recommended Preventive Measures",12,True)
    for r in recs: line("• "+r)
    y-=5; line("Safety note: this report is generated from the CyberGraud controlled/synthetic security environment.",9)
    c.showPage(); c.save(); buf.seek(0)
    return StreamingResponse(buf,media_type="application/pdf",headers={"Content-Disposition":f"attachment; filename=cybergraud_event_{event_id}.pdf"})

@app.get("/api/export/events.csv")
def export_events(user=Depends(current_user)):
    conn=connect(); rows=conn.execute("SELECT id,mode,source,target,attack_type,prediction,risk,confidence,malicious_probability,created_at FROM events WHERE user_id=? ORDER BY id DESC",(user["id"],)).fetchall(); conn.close()
    out=io.StringIO(); writer=csv.writer(out); writer.writerow(["ID","Mode","Source","Target","Attack Type","Prediction","Risk","Confidence","Malicious Probability","Created At"])
    writer.writerows([list(r) for r in rows]); out.seek(0)
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=cybergraud_events.csv"})
