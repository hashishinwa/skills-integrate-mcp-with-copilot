"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import hashlib
import json
import os
import secrets
from pathlib import Path

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

with open(current_dir / "activities.json", encoding="utf-8") as activities_file:
    activities = json.load(activities_file)

with open(current_dir / "teachers.json", encoding="utf-8") as teachers_file:
    teachers = json.load(teachers_file)

sessions = {}


class LoginRequest(BaseModel):
    username: str
    password: str


def require_teacher(session_token: str | None = Cookie(default=None)):
    if session_token not in sessions:
        raise HTTPException(
            status_code=401,
            detail="Teacher login required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return sessions[session_token]


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/login")
def login(credentials: LoginRequest, response: Response):
    teacher = teachers.get(credentials.username)
    password_hash = hashlib.sha256(credentials.password.encode()).hexdigest()
    if not teacher or not secrets.compare_digest(
        password_hash, teacher["password_hash"]
    ):
        raise HTTPException(status_code=401, detail="Invalid teacher credentials")

    session_token = secrets.token_urlsafe(32)
    sessions[session_token] = credentials.username
    response.set_cookie(
        "session_token",
        session_token,
        httponly=True,
        samesite="lax",
    )
    return {"message": "Logged in", "username": credentials.username}


@app.post("/logout")
def logout(response: Response, session_token: str | None = Cookie(default=None)):
    if session_token:
        sessions.pop(session_token, None)
    response.delete_cookie("session_token")
    return {"message": "Logged out"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, email: str, teacher_username: str = Depends(require_teacher)
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str, email: str, teacher_username: str = Depends(require_teacher)
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
