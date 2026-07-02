# server/app/models.py
from sqlmodel import SQLModel, Field, Relationship
from datetime import datetime
from typing import List, Optional

class Customer(SQLModel, table=True):
    id: str = Field(primary_key=True)
    name: str
    status: str = Field(default="ACTIVE")  # ACTIVE | INACTIVE
    max_licenses: int = Field(default=5)   # Quota limit of licenses
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    licenses: List["License"] = Relationship(back_populates="customer")

class License(SQLModel, table=True):
    id: str = Field(primary_key=True)
    customer_id: str = Field(foreign_key="customer.id")
    name: str  # e.g., "Llama-3-8B-Secured"
    encrypted_dek: str  # Base64 encrypted JSON string of DEK payload
    expires_at: datetime
    max_devices: int = Field(default=3)    # Activation quota limit per license
    is_revoked: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    customer: Customer = Relationship(back_populates="licenses")
    activations: List["Activation"] = Relationship(back_populates="license")

class Activation(SQLModel, table=True):
    id: str = Field(primary_key=True)
    license_id: str = Field(foreign_key="license.id")
    hardware_hash: str  # SHA256(fingerprint)
    hardware_details: str  # JSON list of hardware IDs (encrypted or plain text)
    activation_code: str  # The generated 16-character code
    activated_at: datetime = Field(default_factory=datetime.utcnow)
    
    license: License = Relationship(back_populates="activations")
