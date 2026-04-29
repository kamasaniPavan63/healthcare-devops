# Healthcare Security Platform
## Hybrid Cryptographic Architecture for Healthcare Data Security in Cloud Environments

---

## 🏗️ Project Overview

A fully functional healthcare data security platform implementing **hybrid cryptography** to protect Electronic Health Records (EHRs) in cloud environments.

### Security Architecture

| Algorithm | Purpose | Specification |
|-----------|---------|---------------|
| AES-256-GCM | Record Encryption | 256-bit key, authenticated |
| ECDH | Key Exchange | SECP384R1 curve |
| ECDSA | Digital Signatures | SECP256K1 + SHA-256 |
| SHA-256 | Integrity Hashing | 256-bit fingerprint |

---

## 📁 Project Structure

```
healthcare-security-project/
├── backend/
│   ├── app.py                  # Main Flask application
│   ├── config.py               # Configuration
│   ├── extensions.py           # Flask extensions (SQLAlchemy)
│   ├── requirements.txt        # Python dependencies
│   ├── models/
│   │   ├── user_model.py       # User, Patient, Doctor models
│   │   └── report_model.py     # MedicalReport, ActivityLog models
│   ├── routes/
│   │   ├── auth_routes.py      # Login, register, profile
│   │   ├── admin_routes.py     # Admin management
│   │   ├── doctor_routes.py    # Doctor operations
│   │   ├── patient_routes.py   # Patient operations
│   │   ├── medical_routes.py   # Encrypted report upload/decrypt
│   │   └── decorators.py       # JWT auth decorators
│   └── crypto/
│       ├── aes_module.py       # AES-256-GCM encryption
│       ├── ecdh_module.py      # ECDH key exchange
│       ├── ecdsa_module.py     # ECDSA digital signatures
│       └── sha256_module.py    # SHA-256 hashing
├── frontend/
│   ├── login.html
│   ├── register.html
│   ├── admin_dashboard.html
│   ├── doctor_dashboard.html
│   ├── patient_dashboard.html
│   ├── styles.css
│   └── script.js
└── database/
    └── schema.sql
```

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.9+
- pip
- VS Code (recommended)

### Step 1: Navigate to backend

```bash
cd healthcare-security-project/backend
```

### Step 2: Create virtual environment (recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Run the application

```bash
python app.py
```

### Step 5: Open in browser

```
http://127.0.0.1:5000
```

---

## 🔑 Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@healthcare.com | Admin@1234 |

---

## 👤 User Roles & Workflow

### Admin
- Login → `admin_dashboard.html`
- Approve/suspend/delete users
- Create doctor accounts directly
- View all encrypted records
- Monitor activity logs

### Doctor
- Login → `doctor_dashboard.html`
- View assigned patient records
- Decrypt records (verifies hash + signature first)
- Upload medical reports for patients

### Patient
- Register → Pending admin approval
- Login → `patient_dashboard.html`
- Upload own medical reports (encrypted automatically)
- View/decrypt own records
- Share reports with doctors

### Security Rule
- Admin accounts require `ADMIN_SECRET_KEY` (default: `ADMIN-MASTER-KEY-2024`)
- Patients cannot create admin accounts

---

## 🔐 Cryptographic Workflow

### Encryption (Upload)
```
1. Generate random AES-256 key
2. Encrypt report data with AES-256-GCM
   → Produces: {nonce, ciphertext, tag}
3. Compute SHA-256 hash of:
   → {encrypted_payload + patient_id + doctor_id + report_type}
4. Sign hash with ECDSA (SECP256K1) using uploader's private key
5. Store: encrypted_data, hash, signature, signer_public_key
```

### Decryption (Access)
```
1. Retrieve encrypted record from database
2. Verify SHA-256 hash (integrity check)
3. Verify ECDSA signature (authenticity check)
4. Decrypt with AES-256-GCM using stored key
5. Return plaintext data to authorized user
```

---

## 📡 API Reference

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register patient/doctor |
| POST | `/api/auth/login` | Login, returns JWT |
| GET  | `/api/auth/profile` | Get current user profile |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/admin/dashboard` | Stats + recent activity |
| GET  | `/api/admin/users` | List all users |
| POST | `/api/admin/users/<id>/approve` | Approve user |
| POST | `/api/admin/users/<id>/suspend` | Suspend user |
| DELETE | `/api/admin/users/<id>` | Delete user |
| GET  | `/api/admin/logs` | Activity logs |
| POST | `/api/admin/create-doctor` | Create doctor account |

### Medical Records
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/medical/upload` | Upload encrypted report |
| GET  | `/api/medical/records` | Get records (role-filtered) |
| DELETE | `/api/medical/records/<id>` | Delete record |

### Doctor
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/doctor/dashboard` | Doctor stats |
| GET  | `/api/doctor/patients` | Assigned patients |
| GET  | `/api/doctor/records` | Patient records |
| GET  | `/api/doctor/records/<id>/decrypt` | Decrypt record |

### Patient
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/patient/dashboard` | Patient stats |
| GET  | `/api/patient/records` | Own records |
| GET  | `/api/patient/records/<id>/view` | View+decrypt own record |
| GET  | `/api/patient/doctors` | List available doctors |

---

## 📊 Database Schema

### users
- id, name, email, password_hash, role, status
- ecdsa_public_key, ecdsa_private_key (per-user signing keys)
- ecdh_public_key, ecdh_private_key (per-user key exchange)

### patients
- patient_id, user_id, age, gender, blood_group, medical_history

### doctors
- doctor_id, user_id, specialization, license_number, hospital

### medical_reports
- report_id, patient_id, doctor_id, report_type
- encrypted_data (AES-GCM JSON), wrapped_key, hash_value (SHA-256), signature (ECDSA)

### activity_logs
- log_id, user_id, action, resource, ip_address, timestamp

---

## 🩺 Supported Report Types

| Type | Fields |
|------|--------|
| vital_signs | BP systolic/diastolic, heart rate, respiratory rate, temperature, O₂ sat |
| blood_test | Hemoglobin, RBC, WBC, platelets, glucose, cholesterol, HDL, LDL, triglycerides |
| imaging | Imaging type, body part, findings, radiologist notes, scan date |
| prescription | Medication, dosage, frequency, duration, doctor notes |

---

## ⚙️ Configuration (config.py)

```python
SECRET_KEY = 'your-secret-key'          # JWT signing key
ADMIN_SECRET_KEY = 'ADMIN-MASTER-KEY'   # Required for admin registration
SQLALCHEMY_DATABASE_URI = 'sqlite:///healthcare.db'
```

---

## 🛡️ Security Notes

1. **Private keys** are stored in the database unencrypted for demo purposes. In production, encrypt with a KMS.
2. **AES key** is stored as base64. In production, wrap with recipient's ECDH public key.
3. **JWT tokens** expire after 8 hours.
4. **Passwords** are hashed with Werkzeug's PBKDF2-SHA256.
5. All API endpoints require Bearer token authentication.
# healthcare-devops
# healthcare-devops
