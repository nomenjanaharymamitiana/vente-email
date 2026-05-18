from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    password = Column(String(128), nullable=False)
    phone = Column(String(30), nullable=False)
    role = Column(String, default="client")  # "client" ou "admin"

    orders = relationship("EmailOrder", back_populates="user")
    payout_requests = relationship("PayoutRequest", back_populates="user")


class EmailOrder(Base):
    __tablename__ = "email_orders"

    id = Column(Integer, primary_key=True, index=True)
    email_submitted = Column(String(255), nullable=False)
    email_password = Column(String(255), nullable=False)
    price = Column(Float, default=1000.0, nullable=False)
    status = Column(String(20), default="En attente", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="orders")


class AppSetting(Base):
    __tablename__ = "app_settings"

    key = Column(String(80), primary_key=True)
    value = Column(String(255), nullable=False)


class PayoutRequest(Base):
    __tablename__ = "payout_requests"

    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float, nullable=False)
    status = Column(String(20), default="En attente", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="payout_requests")
