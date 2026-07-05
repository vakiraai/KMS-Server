# backend/app/main.py
import os
import uuid
import json
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .database import create_db_and_tables, get_session
from .models import Customer, License, Activation
from .crypto_utils import generate_key, encrypt_data, decrypt_data, derive_kek

raw_secret = os.getenv("SERVER_SECRET", "vajraa_kms_master_secret_key_2026")
SERVER_SECRET = hashlib.sha256(raw_secret.encode("utf-8")).digest()

# Asymmetric Ed25519 keys derived deterministically from SERVER_SECRET
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(SERVER_SECRET)
public_key = private_key.public_key()
PUBLIC_KEY_HEX = public_key.public_bytes_raw().hex()

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
    print(f"\n=====================================================================")
    print(f"VAJRAA KMS SERVER STARTED (Asymmetric Signing Mode)")
    print(f"Ed25519 Verification Key to embed in Client SDK:")
    print(f"👉 PUBLIC_KEY_HEX = \"{PUBLIC_KEY_HEX}\"")
    print(f"=====================================================================\n")

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
# CRYPTO HELPERS
# =====================================================================

def derive_kek_asymmetric(signature: bytes, fingerprint_hash: str) -> bytes:
    """Derives a 256-bit KEK from the Ed25519 signature & hardware fingerprint."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=fingerprint_hash.encode("utf-8"),
        info=b"vajraa_asymmetric_kek_derivation",
        backend=default_backend()
    )
    return hkdf.derive(signature)

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
    
    # Wrap temporarily with server secret key for database storage
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
    registers the activation, signs the lease via Ed25519, and returns the token.
    """
    try:
        # Try as plain base64 QR payload first (asymmetric flow)
        try:
            payload_bytes = base64.b64decode(payload.data)
            data_dict = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            # Fallback to symmetric decryption for backward compatibility
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
        
    expires_at_str = lic.expires_at.isoformat()
    
    # 1. Asymmetric Ed25519 signature on canonical verification string
    canonical_payload = f"{license_id}:{fingerprint_hash}:{expires_at_str}"
    signature = private_key.sign(canonical_payload.encode("utf-8"))
    signature_hex = signature.hex()
    
    # 2. Derive KEK using the signature and fingerprint hash via HKDF
    kek = derive_kek_asymmetric(signature, fingerprint_hash)
    
    # 3. Decrypt original DEK
    stored_dek_dict = json.loads(lic.encrypted_dek)
    dek = decrypt_data(stored_dek_dict, SERVER_SECRET)
    
    # 4. Wrap DEK with our derived asymmetric KEK
    wrapped_dek_dict = encrypt_data(dek, kek)
    
    # 5. Pack complete token (Base64 JSON containing payload, signature, and wrapped DEK)
    token_payload = {
        "license_id": license_id,
        "fingerprint_hash": fingerprint_hash,
        "expires_at": expires_at_str,
        "signature": signature_hex,
        "wrapped_dek": wrapped_dek_dict
    }
    activation_token = base64.b64encode(json.dumps(token_payload).encode("utf-8")).decode("utf-8")
    
    # Short 16-character human-friendly code derived via HMAC of the signature
    h = hmac.new(SERVER_SECRET, signature, hashlib.sha256).digest()
    b32 = base64.b32encode(h).decode("utf-8").replace("=", "")
    activation_code = f"{b32[0:4]}-{b32[4:8]}-{b32[8:12]}-{b32[12:16]}"
    
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
        
    expires_at_str = lic.expires_at.isoformat()
    
    # 1. Asymmetric Ed25519 signature
    canonical_payload = f"{license_id}:{fingerprint_hash}:{expires_at_str}"
    signature = private_key.sign(canonical_payload.encode("utf-8"))
    signature_hex = signature.hex()
    
    # 2. Derive KEK
    kek = derive_kek_asymmetric(signature, fingerprint_hash)
    
    # 3. Decrypt/Unwrap DEK
    stored_dek_dict = json.loads(lic.encrypted_dek)
    dek = decrypt_data(stored_dek_dict, SERVER_SECRET)
    
    # 4. Wrap DEK
    wrapped_dek_dict = encrypt_data(dek, kek)
    
    # 5. Short code
    h = hmac.new(SERVER_SECRET, signature, hashlib.sha256).digest()
    b32 = base64.b32encode(h).decode("utf-8").replace("=", "")
    activation_code = f"{b32[0:4]}-{b32[4:8]}-{b32[8:12]}-{b32[12:16]}"
    
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
        "signature": signature_hex,
        "wrapped_dek": wrapped_dek_dict,
        "expires_at": expires_at_str
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
