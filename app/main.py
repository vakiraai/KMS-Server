# server/app/main.py
import os
import uuid
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .database import create_db_and_tables, get_session
from .models import Customer, License, Activation
from .crypto_utils import generate_key, encrypt_data, decrypt_data, derive_kek, generate_activation_code

raw_secret = os.getenv("SERVER_SECRET", "vajraa_kms_master_secret_key_2026")
SERVER_SECRET = hashlib.sha256(raw_secret.encode("utf-8")).digest()

app = FastAPI(title="Vajraa Licensing Server")

# Compute absolute template and static directories relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Create directories if they do not exist
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)

# Mount static and templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

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
# ADMIN API & DASHBOARD ROUTES
# =====================================================================

@app.get("/admin", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, session: Session = Depends(get_session), admin: str = Depends(authenticate_admin)):
    """Renders the HTML Admin Dashboard with customer, license, and activation lists."""
    customers = session.exec(select(Customer)).all()
    licenses = session.exec(select(License)).all()
    activations = session.exec(select(Activation)).all()
    
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "customers": customers,
            "licenses": licenses,
            "activations": activations
        }
    )

@app.post("/admin/customer")
def create_customer(
    id: str = Form(...),
    name: str = Form(...),
    max_licenses: int = Form(5),
    session: Session = Depends(get_session),
    admin: str = Depends(authenticate_admin)
):
    """Registers a new customer account with a fixed license quota."""
    existing = session.get(Customer, id)
    if existing:
        raise HTTPException(status_code=400, detail="Customer ID already exists")
    
    customer = Customer(id=id, name=name, max_licenses=max_licenses)
    session.add(customer)
    session.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/license")
def create_license(
    customer_id: str = Form(...),
    name: str = Form(...),
    trial_days: int = Form(30),
    max_devices: int = Form(3),
    target_fingerprint: Optional[str] = Form(None),
    session: Session = Depends(get_session),
    admin: str = Depends(authenticate_admin)
):
    """
    Generates a new model license.
    Automatically generates a random 256-bit DEK, wraps it, and issues the license metadata.
    """
    customer = session.get(Customer, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
        
    # Check customer license quota
    active_licenses = session.exec(select(License).where(License.customer_id == customer_id, License.is_revoked == False)).all()
    if len(active_licenses) >= customer.max_licenses:
        raise HTTPException(status_code=400, detail=f"Quota exceeded. Customer limit is {customer.max_licenses} licenses.")
        
    license_id = f"LIC-{uuid.uuid4().hex[:8].upper()}"
    dek = generate_key()
    
    # Envelope Encryption:
    # If a pre-bound target fingerprint is provided, wrap it with the target KEK immediately.
    # Otherwise, store it wrapped with the server key (to be re-wrapped with KEK upon client activation).
    if target_fingerprint:
        kek = derive_kek(target_fingerprint, SERVER_SECRET)
        wrapped_dek_dict = encrypt_data(dek, kek)
    else:
        # Wrap temporarily with server key
        wrapped_dek_dict = encrypt_data(dek, SERVER_SECRET)
        
    license_obj = License(
        id=license_id,
        customer_id=customer_id,
        name=name,
        encrypted_dek=json.dumps(wrapped_dek_dict),
        expires_at=datetime.utcnow() + timedelta(days=trial_days),
        max_devices=max_devices
    )
    session.add(license_obj)
    session.commit()
    
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/license/revoke/{license_id}")
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
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

# =====================================================================
# CLIENT HANDSHAKE & ACTIVATION ENDPOINTS (HYBRID FLOW)
# =====================================================================

@app.get("/activate", response_class=HTMLResponse)
def get_activation_page(request: Request, data: str, session: Session = Depends(get_session)):
    """
    Activation endpoint accessed by scanning the offline terminal QR code.
    Decrypts fingerprint payload, checks quotas, issues the activation token.
    """
    try:
        # Decrypt incoming QR payload using Server Secret
        payload_bytes = decrypt_data(json.loads(data), SERVER_SECRET)
        payload = json.loads(payload_bytes.decode("utf-8"))
        
        license_id = payload["license_id"]
        fingerprint_hash = payload["fingerprint_hash"]
        hardware_details = payload.get("hardware_details", "{}")
        
    except Exception:
        return templates.TemplateResponse(request=request, name="activate_error.html", context={"detail": "Invalid QR Activation Payload"})
        
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        return templates.TemplateResponse(request=request, name="activate_error.html", context={"detail": "License is invalid or revoked"})
        
    if lic.expires_at < datetime.utcnow():
        return templates.TemplateResponse(request=request, name="activate_error.html", context={"detail": "License trial period has expired"})
        
    # Check activation device limit
    existing_activations = session.exec(select(Activation).where(Activation.license_id == license_id)).all()
    device_already_active = any(act.hardware_hash == fingerprint_hash for act in existing_activations)
    
    if not device_already_active and len(existing_activations) >= lic.max_devices:
        return templates.TemplateResponse(request=request, name="activate_error.html", context={"detail": f"Activation limit reached ({lic.max_devices} devices)."})
        
    # Generate 16-character HMAC code
    activation_code = generate_activation_code(fingerprint_hash, license_id, SERVER_SECRET)
    
    # Decrypt original DEK
    stored_dek_dict = json.loads(lic.encrypted_dek)
    dek = decrypt_data(stored_dek_dict, SERVER_SECRET)
    
    # Wrap DEK with client KEK derived from fingerprint
    kek = derive_kek(fingerprint_hash, SERVER_SECRET)
    wrapped_dek_dict = encrypt_data(dek, kek)
    
    # Combine activation code and wrapped DEK into a single Base64 activation token string (approx 80 chars)
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
        
    return templates.TemplateResponse(
        request=request,
        name="activate.html",
        context={
            "activation_code": activation_code,
            "activation_token": activation_token,
            "license_name": lic.name,
            "customer_id": lic.customer_id
        }
    )

@app.post("/api/activate")
def api_activate(request: Request, payload: dict, session: Session = Depends(get_session)):
    """
    API endpoint for direct online client activation checks.
    Automates handshake, returns the activation token directly.
    """
    try:
        # Decrypt dynamic payload or verify signature
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
        
    # Generate verification components
    activation_code = generate_activation_code(fingerprint_hash, license_id, SERVER_SECRET)
    
    # Unwrap stored DEK
    stored_dek_dict = json.loads(lic.encrypted_dek)
    dek = decrypt_data(stored_dek_dict, SERVER_SECRET)
    
    # Wrap DEK with client KEK
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
    """
    API endpoint for periodic online client verification.
    """
    license_id = payload.get("license_id")
    fingerprint_hash = payload.get("fingerprint_hash")
    
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        return {"status": "REVOKED", "message": "License has been revoked"}
        
    if lic.expires_at < datetime.utcnow():
        return {"status": "EXPIRED", "message": "License has expired"}
        
    # Verify device fingerprint is active
    activation = session.exec(select(Activation).where(Activation.license_id == license_id, Activation.hardware_hash == fingerprint_hash)).first()
    if not activation:
        return {"status": "NOT_ACTIVATED", "message": "Device not activated"}
        
    return {
        "status": "ACTIVE",
        "expires_at": lic.expires_at.isoformat()
    }
