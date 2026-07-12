from sqlalchemy import Column, Integer, String, Text
from app.db.database import Base

class RiskReport(Base):
    __tablename__ = "risk_reports"
    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String)
    risk_score = Column(Integer)
    risk_level = Column(String)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String)
    target = Column(String)
    result = Column(Text)
    user_email = Column(String)
