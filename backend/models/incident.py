from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from database import Base


class Incident(Base):

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(
        String(255),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    severity = Column(
        String(50),
        nullable=False,
        default="medium"
    )

    status = Column(
        String(50),
        nullable=False,
        default="open"
    )

    assigned_to = Column(
        String(100),
        nullable=True
    )

    response_action = Column(
        Text,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )