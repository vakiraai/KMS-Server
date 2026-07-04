# Vajraa Key Management Server (KMS)

A self-contained, enterprise-grade Key Management and Licensing Server built with FastAPI. It handles hybrid online/offline device activation, licensing quotas, dynamic trial periods, hardware-locked key derivation (envelope encryption), and clock-tampering detection for the **Vajraa** AI Model Protection SDK.

---

## Key Features

- **Envelope Encryption (DEK/KEK)**: Model weights are encrypted once with a Data Encryption Key (DEK). The KMS wraps the DEK with a Key Encryption Key (KEK) derived from the target machine's hardware fingerprint. If hardware changes, the server simply issues a new 32-byte wrapped DEK without requiring re-encryption of the model weights.
- **Fuzzy Fingerprint Matching (2-of-4 Gate)**: Collects MAC address, Motherboard UUID, Drive Serial, and CPU ID. Validates offline activations if any 2 of the 4 match, allowing seamless hardware upgrades and virtual machine migrations.
- **Clock Windback Protection**: Detects system clock tampering using client-side monotonic state logging (`~/.vajraa/state.bin`) to reject negative time travel attempts.
- **Hybrid Online/Offline Activation**: Connected nodes check licensing and activate silently over HTTP. Offline/air-gapped nodes display a terminal-friendly QR code to scan with a smartphone, redirecting to a mobile-friendly HTML validation page displaying a 16-character code.
- **Admin Dashboard**: Secure, glassmorphism-styled React web application interface (`/`) to register customers, configure license quotas, set trial durations, monitor active device activations, and revoke keys.

---

## Project Structure

```text
vajra-licensing-server/
├── backend/                # FastAPI REST API (Python)
│   ├── app/
│   │   ├── main.py         # REST Endpoints (returns JSON, handles CORS)
│   │   ├── models.py       # SQLModel DB Schema
│   │   ├── database.py     # DB Connection Pool
│   │   └── crypto_utils.py # Cryptographic primitives
│   └── requirements.txt
├── web/                    # React Frontend SPA (Vite)
│   ├── src/
│   │   ├── components/     # Reusable components
│   │   ├── pages/          # Login, Dashboard, Activate screens
│   │   └── App.jsx         # State & Routing
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## Local Setup & Quickstart

### 1. Backend REST API Setup
Initialize a virtual environment and install dependencies:
```bash
cd backend
python -m venv venv
venv\Scripts\activate      # On Windows
source venv/bin/activate    # On Linux/macOS

pip install -r requirements.txt
```

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

Launch the backend REST service:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Frontend React App Setup
Install packages and configure endpoints:
```bash
cd ../web
npm install
```

Configure the environment variables (e.g. create a `.env` file):
```bash
VITE_API_URL=http://localhost:8000
```

Launch the frontend dev server:
```bash
npm run dev
```
Visit the Admin Dashboard at: **`http://localhost:5173`** (log in using your `ADMIN_USER` and `ADMIN_PASS` credentials).

---

## No-Domain / Local LAN Configuration

If you do not have a registered domain name (e.g., in local testing, offline setups, or staging networks), configure the SDK client and KMS server using local IP addresses:

### 1. Client-Side (Vajraa SDK)
Configure the environment variable `VAJRAA_LICENSE_SERVER` on client machines to point to your backend IP:
* **Windows PowerShell:**
  ```powershell
  $env:VAJRAA_LICENSE_SERVER="http://192.168.1.50:8000"
  ```
* **Linux/macOS Bash:**
  ```bash
  export VAJRAA_LICENSE_SERVER="http://192.168.1.50:8000"
  ```

### 2. Server-Side (KMS Server Redirect)
Because scanning the QR code redirects the user's phone browser, configure the `FRONTEND_URL` on the KMS server to point to your React frontend IP:
```bash
# Set on the backend before running uvicorn
$env:FRONTEND_URL="http://192.168.1.50:5173"
```
The backend `/activate` QR redirect will automatically forward the phone's browser to the correct page on your local network.

---

## Application Walkthrough

### 1. Admin Dashboard (`/`)
- **Register Customer**: Add a client (e.g., `AcmeCorp`) and define their max license limit.
- **Issue License**: Assign a license key to a customer, specify the application/model name (e.g. `Llama-3-8B`), set the trial/validity period (e.g. 30 days), and define device quotas (`max_devices`).
- **Activation Table**: View active device fingerprints and see which hardware has registered.
- **Revocation**: Click "Revoke" on any license key to immediately disable key retrieval or activation checks for online nodes.

### 2. QR Code Mobile Activation (`/activate`)
- When an air-gapped device starts the model, the console renders a QR code.
- Scanning the QR Code opens the smartphone's browser to `http://<backend-ip>:8000/activate?data=<encrypted_fingerprint>`.
- The server redirects the browser to the React front-end page at `http://<frontend-ip>:5173/activate?data=<encrypted_fingerprint>`.
- The React page sends a request to the backend `api/activate/offline` to register the device and display the **16-Character Activation Code** and the **Base64 Activation Token**.
- The user types/pastes this token into the offline device terminal to unlock the Data Encryption Key (DEK) and begin inference.
