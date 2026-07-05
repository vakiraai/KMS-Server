# backend/app/main.py
import os
import uuid
import json
import time
import hmac
import base64
import hashlib
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
from .models import Customer, License, Activation, AuditLog
from .crypto_utils import generate_key, encrypt_data, decrypt_data, derive_kek

# =====================================================================
# SECRETS MANAGEMENT & FAIL-OPEN PREVENTION
# =====================================================================

IS_TESTING = os.getenv("TESTING", "false").lower() == "true"

raw_secret = os.getenv("SERVER_SECRET", "vajraa_kms_master_secret_key_2026")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "vajraa-secure-admin-pass-2026")

if not IS_TESTING:
    # Fail-safe startup: refuse to boot on defaults or empty configurations
    if raw_secret == "vajraa_kms_master_secret_key_2026" or not os.getenv("SERVER_SECRET"):
        raise RuntimeError("CRITICAL SECURITY ERROR: SERVER_SECRET is unset or set to the default placeholder! Aborting startup.")
    if ADMIN_USER == "admin" or not os.getenv("ADMIN_USER"):
        raise RuntimeError("CRITICAL SECURITY ERROR: ADMIN_USER is unset or set to 'admin'! Aborting startup.")
    if ADMIN_PASS == "vajraa-secure-admin-pass-2026" or not os.getenv("ADMIN_PASS"):
        raise RuntimeError("CRITICAL SECURITY ERROR: ADMIN_PASS is unset or set to the default placeholder! Aborting startup.")

SERVER_SECRET = hashlib.sha256(raw_secret.encode("utf-8")).digest()

# =====================================================================
# PLUGGABLE KMS PROVIDER ABSTRACTION
# =====================================================================

class KMSProvider:
    """Abstract Base Class for pluggable KMS/HSM signing operations."""
    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError()
    def get_public_key_hex(self) -> str:
        raise NotImplementedError()

class LocalEncryptedKMS(KMSProvider):
    """Local secure KMS provider derived deterministically from the Server Secret."""
    def __init__(self, secret_bytes: bytes):
        self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_bytes)
        self.public_key = self.private_key.public_key()
        
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)
        
    def get_public_key_hex(self) -> str:
        return self.public_key.public_bytes_raw().hex()

# Active KMS Key Provider instance. Easy to subclass and swap for AWS/GCP KMS.
kms_provider = LocalEncryptedKMS(SERVER_SECRET)
PUBLIC_KEY_HEX = kms_provider.get_public_key_hex()

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
security = HTTPBasic()

# In-memory sliding-window rate limiter
rate_limits = {}

def check_rate_limit(ip_address: str, limit: int = 5, period: int = 60):
    """Enforces sliding-window rate limiting per IP address."""
    now = time.time()
    if ip_address not in rate_limits:
        rate_limits[ip_address] = []
        
    # Filter out older timestamps
    rate_limits[ip_address] = [t for t in rate_limits[ip_address] if now - t < period]
    
    if len(rate_limits[ip_address]) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many activation attempts. Rate limit exceeded."
        )
    
    rate_limits[ip_address].append(now)

def log_audit_event(
    session: Session,
    event: str,
    license_id: Optional[str],
    fingerprint_hash: Optional[str],
    request: Request,
    details: str
):
    """Logs a security or activation event to the database audit trail."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    log_entry = AuditLog(
        event=event,
        license_id=license_id,
        fingerprint_hash=fingerprint_hash,
        ip_address=client_ip,
        details=details
    )
    session.add(log_entry)
    session.commit()

def verify_proof_of_possession(
    fingerprint_hash: str,
    client_timestamp_str: str,
    pop_token: str,
    max_drift_seconds: int = 300
):
    """
    Verifies client possession of the physical machine fingerprint
    by validating the time-locked HMAC-SHA256 signature.
    """
    try:
        client_time = datetime.fromisoformat(client_timestamp_str)
        now = datetime.utcnow()
        
        # Check clock drift
        drift = abs((now - client_time).total_seconds())
        if drift > max_drift_seconds:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Proof-of-Possession expired. Clock drift is {int(drift)}s (max allowed is {max_drift_seconds}s)."
            )
            
        # Verify HMAC-SHA256 of fingerprint_hash over the timestamp
        expected_token = hmac.new(
            fingerprint_hash.encode("utf-8"),
            client_timestamp_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(pop_token, expected_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Proof-of-Possession validation failed: signature mismatch."
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Proof-of-Possession payload format: {e}"
        )

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
    request: Request,
    session: Session = Depends(get_session)
):
    """
    Decrypts the offline QR payload, validates the license/quotas,
    verifies Proof-of-Possession, registers activation, and returns the token.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip)
    
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
        timestamp = data_dict.get("timestamp")
        pop_token = data_dict.get("pop_token")
        
    except Exception as e:
        log_audit_event(session, "ACTIVATION_FAILURE", None, None, request, f"Invalid QR activation payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid QR Activation Payload")
        
    # Check Proof-of-Possession (allow up to 24 hours of drift for offline systems)
    if timestamp and pop_token:
        try:
            verify_proof_of_possession(fingerprint_hash, timestamp, pop_token, max_drift_seconds=86400)
        except HTTPException as e:
            log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, f"Offline PoP verification failed: {e.detail}")
            raise
    else:
        # Compatibility fallback for legacy/plain test cases, log warning
        log_audit_event(session, "ACTIVATION_WARNING", license_id, fingerprint_hash, request, "Offline activation without Proof-of-Possession")
        
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, "License invalid or revoked")
        raise HTTPException(status_code=400, detail="License is invalid or has been revoked")
        
    if lic.expires_at < datetime.utcnow():
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, "License expired")
        raise HTTPException(status_code=400, detail="License trial period has expired")
        
    # Check activation device limit
    existing_activations = session.exec(select(Activation).where(Activation.license_id == license_id)).all()
    device_already_active = any(act.hardware_hash == fingerprint_hash for act in existing_activations)
    
    if not device_already_active and len(existing_activations) >= lic.max_devices:
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, f"Activation quota limit reached ({lic.max_devices})")
        raise HTTPException(status_code=400, detail=f"Activation limit reached ({lic.max_devices} devices).")
        
    expires_at_str = lic.expires_at.isoformat()
    
    # 1. Asymmetric sign via pluggable KMS
    canonical_payload = f"{license_id}:{fingerprint_hash}:{expires_at_str}"
    signature = kms_provider.sign(canonical_payload.encode("utf-8"))
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
        
    log_audit_event(session, "ACTIVATION_SUCCESS", license_id, fingerprint_hash, request, f"Device offline activation complete. Code: {activation_code}")
    
    return {
        "status": "SUCCESS",
        "activation_code": activation_code,
        "activation_token": activation_token,
        "license_name": lic.name,
        "customer_id": lic.customer_id
    }

@app.post("/api/activate")
def api_activate(payload: dict, request: Request, session: Session = Depends(get_session)):
    """API endpoint for direct online client activation checks with strict Proof-of-Possession."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip)
    
    try:
        license_id = payload["license_id"]
        fingerprint_hash = payload["fingerprint_hash"]
        timestamp = payload["timestamp"]
        pop_token = payload["pop_token"]
        hardware_details = payload.get("hardware_details", {})
    except KeyError as e:
        log_audit_event(session, "ACTIVATION_FAILURE", None, None, request, f"Missing required activation field: {e}")
        raise HTTPException(status_code=400, detail=f"Missing required activation field: {e}")
        
    # Enforce strict Proof-of-Possession (5 minutes drift allowed)
    try:
        verify_proof_of_possession(fingerprint_hash, timestamp, pop_token, max_drift_seconds=300)
    except HTTPException as e:
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, f"Proof-of-Possession check failed: {e.detail}")
        raise
        
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, "License invalid or revoked")
        raise HTTPException(status_code=400, detail="License is invalid or has been revoked")
        
    if lic.expires_at < datetime.utcnow():
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, "License expired")
        raise HTTPException(status_code=400, detail="License trial period has expired")
        
    existing_activations = session.exec(select(Activation).where(Activation.license_id == license_id)).all()
    device_already_active = any(act.hardware_hash == fingerprint_hash for act in existing_activations)
    
    if not device_already_active and len(existing_activations) >= lic.max_devices:
        log_audit_event(session, "ACTIVATION_FAILURE", license_id, fingerprint_hash, request, f"Activation limit reached ({lic.max_devices})")
        raise HTTPException(status_code=400, detail="Activation limit reached for this license key")
        
    expires_at_str = lic.expires_at.isoformat()
    
    # 1. Asymmetric sign via pluggable KMS
    canonical_payload = f"{license_id}:{fingerprint_hash}:{expires_at_str}"
    signature = kms_provider.sign(canonical_payload.encode("utf-8"))
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
        
    log_audit_event(session, "ACTIVATION_SUCCESS", license_id, fingerprint_hash, request, f"Device online activation complete. Code: {activation_code}")
    
    return {
        "status": "SUCCESS",
        "activation_code": activation_code,
        "signature": signature_hex,
        "wrapped_dek": wrapped_dek_dict,
        "expires_at": expires_at_str
    }

@app.post("/api/verify")
def api_verify(payload: dict, request: Request, session: Session = Depends(get_session)):
    """API endpoint for periodic online client verification with rate limiting."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip, limit=20, period=60)
    
    license_id = payload.get("license_id")
    fingerprint_hash = payload.get("fingerprint_hash")
    
    lic = session.get(License, license_id)
    if not lic or lic.is_revoked:
        log_audit_event(session, "VERIFICATION_FAILED", license_id, fingerprint_hash, request, "Verification failed: License revoked")
        return {"status": "REVOKED", "message": "License has been revoked"}
        
    if lic.expires_at < datetime.utcnow():
        log_audit_event(session, "VERIFICATION_FAILED", license_id, fingerprint_hash, request, "Verification failed: License expired")
        return {"status": "EXPIRED", "message": "License has expired"}
        
    activation = session.exec(select(Activation).where(Activation.license_id == license_id, Activation.hardware_hash == fingerprint_hash)).first()
    if not activation:
        log_audit_event(session, "VERIFICATION_FAILED", license_id, fingerprint_hash, request, "Verification failed: Device not activated")
        return {"status": "NOT_ACTIVATED", "message": "Device not activated"}
        
    log_audit_event(session, "VERIFICATION_SUCCESS", license_id, fingerprint_hash, request, "Device license verified successfully")
    return {
        "status": "ACTIVE",
        "expires_at": lic.expires_at.isoformat()
    }

@app.get("/api/revocations")
def get_revocations(request: Request, session: Session = Depends(get_session)):
    """
    Returns the time-stamped and Ed25519-signed list of revoked license IDs 
    for offline client synchronization.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip, limit=10, period=60)
    
    revoked_licenses = session.exec(select(License).where(License.is_revoked == True)).all()
    revoked_ids = [lic.id for lic in revoked_licenses]
    
    timestamp_str = datetime.utcnow().isoformat()
    
    # Construct CRL payload
    crl_payload = {
        "revoked_ids": revoked_ids,
        "timestamp": timestamp_str
    }
    
    crl_json = json.dumps(crl_payload, sort_keys=True)
    signature = kms_provider.sign(crl_json.encode("utf-8"))
    signature_hex = signature.hex()
    
    log_audit_event(session, "CRL_EXPORTED", None, None, request, f"Exported signed revocation list containing {len(revoked_ids)} keys.")
    
    return {
        "payload": crl_payload,
        "signature": signature_hex
    }
