from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.security_event import SecurityEvent
from models.incident import Incident
from auth.auth import get_current_user


router = APIRouter(
    prefix="/security-operations",
    tags=["Security Operations"]
)


# ---------------------------------------------------------
# Request models
# ---------------------------------------------------------

class EventCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = "medium"
    message: str = Field(min_length=1, max_length=5000)
    source: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    severity: str = "medium"
    description: str | None = None


class IncidentUpdate(BaseModel):
    status: str | None = None
    assigned_to: str | None = Field(default=None, max_length=100)
    description: str | None = None


class InvestigationUpdate(BaseModel):
    findings: str = Field(min_length=1, max_length=10000)


class ResponseUpdate(BaseModel):
    response_action: str = Field(min_length=1, max_length=10000)


# ---------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------

VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical"
}

VALID_STATUSES = {
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed"
}


def validate_severity(severity: str):

    if severity.lower() not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid severity. Use low, medium, "
                "high or critical."
            )
        )


def get_incident_or_404(
    incident_id: int,
    db: Session
):

    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident


# ---------------------------------------------------------
# Security Events
# ---------------------------------------------------------

@router.post("/events")
def create_event(
    payload: EventCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    validate_severity(payload.severity)

    event = SecurityEvent(
        event_type=payload.event_type,
        severity=payload.severity.lower(),
        message=payload.message,
        source=payload.source,
        source_ip=payload.source_ip,
        status="new"
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return {
        "message": "Security event created",
        "event_id": event.id,
        "created_by": current_user["username"]
    }


@router.get("/events")
def get_events(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .all()
    )

    return {
        "count": len(events),
        "events": events
    }


# ---------------------------------------------------------
# Incident Management
# ---------------------------------------------------------

@router.post("/incidents")
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    validate_severity(payload.severity)

    incident = Incident(
        title=payload.title,
        severity=payload.severity.lower(),
        description=payload.description,
        status="open"
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident created",
        "incident_id": incident.id,
        "created_by": current_user["username"]
    }


@router.get("/incidents")
def get_incidents(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .all()
    )

    return {
        "count": len(incidents),
        "incidents": incidents
    }


# ---------------------------------------------------------
# Update Incident / Assign Analyst
# ---------------------------------------------------------

@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    updates = payload.model_dump(
        exclude_unset=True
    )

    if "status" in updates:

        status = updates["status"]

        if status is not None and status not in VALID_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Invalid status. Use open, investigating, "
                    "contained, resolved or closed."
                )
            )

    for field, value in updates.items():

        setattr(
            incident,
            field,
            value
        )

    incident.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident updated",
        "incident_id": incident.id,
        "updated_by": current_user["username"],
        "incident": {
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "assigned_to": incident.assigned_to,
            "description": incident.description
        }
    }


# ---------------------------------------------------------
# Investigation
# ---------------------------------------------------------

@router.post(
    "/incidents/{incident_id}/investigation"
)
def update_investigation(
    incident_id: int,
    payload: InvestigationUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    timestamp = datetime.utcnow().isoformat()

    entry = (
        f"\n\n[Investigation - {timestamp} - "
        f"{current_user['username']}]\n"
        f"{payload.findings}"
    )

    incident.description = (
        (incident.description or "")
        + entry
    )

    if incident.status == "open":
        incident.status = "investigating"

    incident.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(incident)

    return {
        "message": "Investigation findings recorded",
        "incident_id": incident.id,
        "status": incident.status,
        "updated_by": current_user["username"]
    }


# ---------------------------------------------------------
# Incident Response
# ---------------------------------------------------------

@router.post(
    "/incidents/{incident_id}/response"
)
def update_response(
    incident_id: int,
    payload: ResponseUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    incident = get_incident_or_404(
        incident_id,
        db
    )

    timestamp = datetime.utcnow().isoformat()

    entry = (
        f"\n\n[Response - {timestamp} - "
        f"{current_user['username']}]\n"
        f"{payload.response_action}"
    )

    incident.response_action = (
        (incident.response_action or "")
        + entry
    )

    incident.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(incident)

    return {
        "message": "Response action recorded",
        "incident_id": incident.id,
        "status": incident.status,
        "updated_by": current_user["username"]
    }