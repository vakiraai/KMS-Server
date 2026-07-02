# Vajraa Key Management Server (KMS)

A self-contained, enterprise-grade Key Management and Licensing Server built with FastAPI. It handles hybrid online/offline device activation, licensing quotas, dynamic trial periods, hardware-locked key derivation (envelope encryption), and clock-tampering detection for the **Vajraa** AI Model Protection SDK.

---

## Key Features

- **Envelope Encryption (DEK/KEK)**: Model weights are encrypted once with a Data Encryption Key (DEK). The KMS wraps the DEK with a Key Encryption Key (KEK) derived from the target machine's hardware fingerprint. If hardware changes, the server simply issues a new 32-byte wrapped DEK without requiring re-encryption of the model weights.
- **Fuzzy Fingerprint Matching (2-of-4 Gate)**: Collects MAC address, Motherboard UUID, Drive Serial, and CPU ID. Validates offline activations if any 2 of the 4 match, allowing seamless hardware upgrades and virtual machine migrations.
- **Clock Windback Protection**: Detects system clock tampering using client-side monotonic state logging (`~/.vajraa/state.bin`) to reject negative time travel attempts.
- **Hybrid Online/Offline Activation**: Connected nodes check licensing and activate silently over HTTP. Offline/air-gapped nodes display a terminal-friendly QR code to scan with a smartphone, redirecting to a mobile-friendly HTML validation page displaying a 16-character code.
- **Admin Dashboard**: Secure, glassmorphism-styled admin interface (`/admin`) to register customers, configure license quotas, set trial durations, monitor active device activations, and revoke keys.

---

## Project Structure

```text
vajra-licensing-server/
├── app/
│   ├── __init__.py
│   ├── main.py             # FastAPI endpoints, activation logic & Admin Auth
│   ├── models.py           # SQLModel DB Schema (Customer, License, Activation)
│   ├── database.py         # DB connection & session creation (SQLite/Postgres)
│   ├── crypto_utils.py     # Self-contained AES-GCM & HMAC code primitives
│   ├── static/             # CSS styling and assets
│   └── templates/          # Jinja2 templates (admin.html, activate.html, error.html)
├── requirements.txt        # Server dependencies
└── README.md               # Setup & Setup Walkthrough
```

---

## Local Setup & Quickstart

### 1. Prerequisites
- Python 3.9 or higher installed.

### 2. Install Dependencies
Initialize a virtual environment and install the required Python dependencies:
```bash
python -m venv venv
venv\Scripts\activate      # On Windows
source venv/bin/activate    # On Linux/macOS

pip install -r requirements.txt
```

### 3. Configure Environments
Set up environment variables to secure your KMS deployment:
```bash
# Admin Auth Credentials
$env:ADMIN_USER="admin"
$env:ADMIN_PASS="your-secure-admin-password"

# Server Cryptographic Salt (MUST be identical on client model compilations)
$env:SERVER_SECRET="your-256bit-master-kms-secret-key"

# Database Connection (Defaults to local SQLite)
$env:DATABASE_URL="sqlite:///./vajraa.db"
```

### 4. Run Server
Launch the server using Uvicorn:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Visit the Admin Dashboard at: **`http://localhost:8000/admin`** (log in using your `ADMIN_USER` and `ADMIN_PASS` credentials).

---

## Database Portability (Production PostgreSQL)

To switch the server from the local SQLite database to a production-ready **PostgreSQL** instance, set the `DATABASE_URL` environment variable to your PostgreSQL connection string:

```bash
$env:DATABASE_URL="postgresql://user:password@localhost:5432/vajraa_db"
```
The application will automatically detect the database type, load the correct connection pooling arguments, and initialize all schema tables on startup.

---

## Application Walkthrough

### 1. Admin Dashboard (`/admin`)
- **Register Customer**: Add a client (e.g., `AcmeCorp`) and define their max license limit.
- **Issue License**: Assign a license key to a customer, specify the application/model name (e.g. `Llama-3-8B`), set the trial/validity period (e.g. 30 days), and define device quotas (`max_devices`).
- **Activation Table**: View active device fingerprints and see which hardware has registered.
- **Revocation**: Click "Revoke" on any license key to immediately disable key retrieval or activation checks for online nodes.

### 2. QR Code Mobile Activation (`/activate`)
- When an air-gapped device starts the model, the console renders a QR code.
- Scanning the QR Code opens the smartphone's browser to `https://kms.vajraa.ai/activate?data=<encrypted_fingerprint>`.
- The server decrypts the payload, validates the license status, and displays the **16-Character Activation Token** (`ABCD-EFGH-IJKL-MNOP`).
- The user types this token into the offline device terminal to unlock the Data Encryption Key (DEK) and begin inference.
