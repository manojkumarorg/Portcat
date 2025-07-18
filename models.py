from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, JSON, DateTime
import datetime

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)
    result = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)