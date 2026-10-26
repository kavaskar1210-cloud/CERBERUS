from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    target_url = Column(String(500), nullable=False)

    status = Column(String(50), nullable=False)
    scan_type = Column(String(50), nullable=False, default="web")

    results = Column(Text, nullable=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )