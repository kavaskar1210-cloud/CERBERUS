from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from database import Base


class SecurityEvent(Base):

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    event_type = Column(String(100), nullable=False)

    severity = Column(
        String(50),
        nullable=False,
        default="medium"
    )

    source = Column(
        String(255),
        nullable=True
    )

    source_ip = Column(
        String(100),
        nullable=True
    )

    message = Column(
        Text,
        nullable=False
    )

    status = Column(
        String(50),
        nullable=False,
        default="new"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )