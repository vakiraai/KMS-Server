# backend/app/main.py
import os
import uuid
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from pydantic import BaseModel

from .database import create_db_and_tables, get_session
from .models import Customer, License, Activation
from .crypto_utils import generate_key, encrypt_data, decrypt_data, derive_kek, generate_activation_code

raw_secret = os.getenv("SERVER_SECRET", "vajraa_kms_master_secret_key_2026")
SERVER_SECRET = hashlib.sha256(raw_secret.encode("utf-8")).digest()

app = FastAPI(title="Vajraa Licensing Server")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Admin credentials
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "vajraa-secure-admin-pass-2026")

security = HTTPBasic()

def authenticate_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """Verifies administrator Basic Authentication credentials."""
    if credentials.username != ADMIN_USER or credentials.password != ADMIN_PASS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect admin username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# =====================================================================
# REQUEST SCHEMAS
# =====================================================================

class CustomerCreate(BaseModel):
    id: str
    name: str
    max_licenses: Optional[int] = 5

class LicenseCreate(BaseModel):
    customer_id: str
    name: str
    trial_days: Optional[int] = 30
    max_devices: Optional[int] = 3
    target_fingerprint: Optional[str] = None

class OfflineActivateRequest(BaseModel):
    data: str

# =====================================================================
# REST API ENDPOINTS
# =====================================================================

@app.get("/api/admin/stats")
def get_admin_stats(session: Session = Depends(get_session), admin: str = Depends(authenticate_admin)):
    """Returns lists of customers, licenses, activations, and key statistics."""
    customers = session.exec(select(Customer)).all()
    licenses = session.exec(select(License)).all()
    activations = session.exec(select(Activation)).all()
    
    return {
        "customers": customers,
        "licenses": licenses,
        "activations": activations,
        "stats": {
            "total_customers": len(customers),
            "total_licenses": len(licenses),
            "total_activations": len(activations),
            "active_devices": len(set(act.hardware_hash for act in activations))
        }
    }

@app.post("/api/admin/customer", status_code=status.HTTP_201_CREATED)
def create_customer(
    payload: CustomerCreate,
    session: Session = Depends(get_session),
    admin: str = Depends(authenticate_admin)
):
    """Registers a new customer account with a fixed license quota."""
    existing = session.get(Customer, payload.id)
    if existing:
        raise HTTPException(status_code=400, detail="Customer ID already exists")
    
    customer = Customer(id=payload.id, name=payload.name, max_licenses=payload.max_licenses)
    session.add(customer)
    session.commit()
    session.refresh(customer)
    return customer

@app.post("/api/admin/license", status_code=status.HTTP_201_CREATED)
def create_license(
    payload: LicenseCreate,
    session: Session = Depends(get_session),
    admin: str = Depends(authenticate_admin)
):
    """Generates a new model license using Envelope Encryption."""
    customer = session.get(Customer, payload.customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
        
    # Check customer license quota
    active_licenses = session.exec(select(License).where(License.customer_id == payload.customer_id, License.is_revoked == False)).all()
    if len(active_licenses) >= customer.max_licenses:
        raise HTTPException(status_code=400, detail=f"Quota exceeded. Customer limit is {customer.max_licenses} licenses.")
        
    license_id = f"LIC-{uuid.uuid4().hex[:8].upper()}"
    dek = generate_key()
    
    # Envelope Encryption KEK derivation
    if payload.target_fingerprint:
        kek = derive_kek(payload.target_fingerprint, SERVER_SECRET)
        wrapped_dek_dict = encrypt_data(dek, kek)
    else:
        # Wrap temporarily with server key
        wrapped_dek_dict = encrypt_data(dek, SERVER_SECRET)
        
    license_obj = License(
        id=license_id,
        customer_id=payload.customer_id,
        name=payload.name,
        encrypted_dek=json.dumps(wrapped_dek_dict),
        expires_at=datetime.utcnow() + timedelta(days=payload.trial_days),
        max_devices=payload.max_devices
    )
    session.add(license_obj)
    session.commit()
    session.refresh(license_obj)
    return license_obj

@app.post("/api/admin/license/revoke/{license_id}")
def revoke_license(
    license_id: str,
    session: Session = Depends(get_session),
    admin: str = Depends(authenticate_admin)
):
    """Revokes a license key to disable activations instantly."""
    lic = session.get(License, license_id)
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    lic.is_revoked = True
    session.add(lic)
    session.commit()
    return {"status": "SUCCESS", "message": f"License {license_id} successfully revoked"}

# =====================================================================
# CLIENT HANDSHAKE & ACTIVATION ENDPOINTS (HYBRID FLOW)
# =====================================================================

@app.get("/activate")
def get_activation_page(data: str):
    """Redirects the mobile phone scan to the React frontend activation page."""
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    return RedirectResponse(url=f"{frontend_url}/activate?data={data}")

@app.post("/api/activate/offline")
def api_activate_offline(
    payload: OfflineActivateRequest,
    session: Session = Depends(get_session)
):
    """
    Decrypts the offline QR payload, validates the license/quotas,
    registers the activation, and returns the 16-character code and KEK-wrapped DEK.
    """
    try:
        # Decrypt incoming QR payload using Server Secret
        payload_bytes = decrypt_data(json.loads(payload.data), SERVER_SECRET)
        data_dict = json.loads(payload_bytes.decode("utf-8"))
        
        license_id = data_dict["license_id"]
        fingerprint_hash = data_dict["fingerprint_hash"]
        hardware_details = data_dict.get("hardware_details", "{}")
        
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid QR Activation Payload")
        
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        raise HTTPException(status_code=400, detail="License is invalid or has been revoked")
        
    if lic.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="License trial period has expired")
        
    # Check activation device limit
    existing_activations = session.exec(select(Activation).where(Activation.license_id == license_id)).all()
    device_already_active = any(act.hardware_hash == fingerprint_hash for act in existing_activations)
    
    if not device_already_active and len(existing_activations) >= lic.max_devices:
        raise HTTPException(status_code=400, detail=f"Activation limit reached ({lic.max_devices} devices).")
        
    # Generate 16-character HMAC code
    activation_code = generate_activation_code(fingerprint_hash, license_id, SERVER_SECRET)
    
    # Decrypt original DEK
    stored_dek_dict = json.loads(lic.encrypted_dek)
    dek = decrypt_data(stored_dek_dict, SERVER_SECRET)
    
    # Wrap DEK with client KEK derived from fingerprint
    kek = derive_kek(fingerprint_hash, SERVER_SECRET)
    wrapped_dek_dict = encrypt_data(dek, kek)
    
    # Combine activation code and wrapped DEK into a single Base64 activation token string
    token_payload = {
        "code": activation_code,
        "wrapped_dek": wrapped_dek_dict
    }
    activation_token = json.dumps(token_payload)
    
    # Register device activation if not already present
    if not device_already_active:
        activation_obj = Activation(
            id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            license_id=license_id,
            hardware_hash=fingerprint_hash,
            hardware_details=json.dumps(hardware_details),
            activation_code=activation_code
        )
        session.add(activation_obj)
        session.commit()
        
    return {
        "status": "SUCCESS",
        "activation_code": activation_code,
        "activation_token": activation_token,
        "license_name": lic.name,
        "customer_id": lic.customer_id
    }

@app.post("/api/activate")
def api_activate(payload: dict, session: Session = Depends(get_session)):
    """API endpoint for direct online client activation checks."""
    try:
        license_id = payload["license_id"]
        fingerprint_hash = payload["fingerprint_hash"]
        hardware_details = payload.get("hardware_details", {})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload format")
        
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        raise HTTPException(status_code=400, detail="License is invalid or has been revoked")
        
    if lic.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="License trial period has expired")
        
    existing_activations = session.exec(select(Activation).where(Activation.license_id == license_id)).all()
    device_already_active = any(act.hardware_hash == fingerprint_hash for act in existing_activations)
    
    if not device_already_active and len(existing_activations) >= lic.max_devices:
        raise HTTPException(status_code=400, detail="Activation limit reached for this license key")
        
    activation_code = generate_activation_code(fingerprint_hash, license_id, SERVER_SECRET)
    
    stored_dek_dict = json.loads(lic.encrypted_dek)
    dek = decrypt_data(stored_dek_dict, SERVER_SECRET)
    
    kek = derive_kek(fingerprint_hash, SERVER_SECRET)
    wrapped_dek_dict = encrypt_data(dek, kek)
    
    if not device_already_active:
        activation_obj = Activation(
            id=f"ACT-{uuid.uuid4().hex[:8].upper()}",
            license_id=license_id,
            hardware_hash=fingerprint_hash,
            hardware_details=json.dumps(hardware_details),
            activation_code=activation_code
        )
        session.add(activation_obj)
        session.commit()
        
    return {
        "status": "SUCCESS",
        "activation_code": activation_code,
        "wrapped_dek": wrapped_dek_dict,
        "expires_at": lic.expires_at.isoformat()
    }

@app.post("/api/verify")
def api_verify(payload: dict, session: Session = Depends(get_session)):
    """API endpoint for periodic online client verification."""
    license_id = payload.get("license_id")
    fingerprint_hash = payload.get("fingerprint_hash")
    
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        return {"status": "REVOKED", "message": "License has been revoked"}
        
    if lic.expires_at < datetime.utcnow():
        return {"status": "EXPIRED", "message": "License has expired"}
        
    activation = session.exec(select(Activation).where(Activation.license_id == license_id, Activation.hardware_hash == fingerprint_hash)).first()
    if not activation:
        return {"status": "NOT_ACTIVATED", "message": "Device not activated"}
        
    return {
        "status": "ACTIVE",
        "expires_at": lic.expires_at.isoformat()
    }
