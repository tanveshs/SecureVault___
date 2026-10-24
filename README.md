# SecureVault: Encrypted Password Manager Using Python

> **Cryptography & Network Security (CNS) / Cybersecurity Mini-Project**  
> Built with Python 3, Flask, SQLite, Argon2id, and Fernet (AES-128-CBC + HMAC-SHA256).

---

## 1. Project Overview & Objective

**SecureVault** is an encrypted password manager developed to demonstrate core principles of applied cryptography, computer network security (CNS), and secure web architecture.

The application allows users to securely store and manage digital credentials (website, username/email, account password, URL, and sensitive notes). 

### Core Security Guarantee:
- **Zero Plaintext Storage:** Passwords and sensitive notes are **NEVER** stored in plaintext inside the SQLite database or in client-side cookies.
- **Zero Master Password Storage:** The master password is never stored anywhere; only its memory-hard Argon2id hash is saved for authentication.
- **Ephemeral Key In-Memory Lifetime:** The vault encryption key is derived on the fly, stored only in volatile server memory during active sessions, and automatically purged upon auto-lock (5 minutes of inactivity) or manual lock.

---

## 2. Cybersecurity Concepts Demonstrated

| Concept | Implementation in SecureVault | Viva Explanation |
| :--- | :--- | :--- |
| **Symmetric Encryption** | Fernet (AES-128 in CBC mode) | Two-way mathematical function to preserve confidentiality of stored credentials. |
| **Integrity & Authenticity** | HMAC-SHA256 with constant-time verification | Guarantees ciphertext cannot be tampered with or altered in SQLite without detection. |
| **Password Hashing** | Argon2id (`argon2-cffi`) | One-way mathematical function. Memory-hard algorithm designed to defeat GPU/ASIC cracking. |
| **Cryptographic Salting** | 16-byte random salt (`os.urandom`) | Unique per vault; renders precomputed rainbow table attacks completely ineffective. |
| **Key Derivation (KDF)** | PBKDF2 with HMAC-SHA256 & 600,000 iterations | Stretches human master password into a 256-bit cryptographic key, heavily slowing brute-force attempts. |
| **CSPRNG** | Python `secrets` module | Cryptographically secure pseudo-random number generation for passwords, salts, and session tokens. |
| **Brute-Force Resistance** | IP-based rate limiter (5 failed attempts → 60s lockout) | Throttles online dictionary and credential-stuffing attacks. |
| **Session Security** | `HTTPOnly`, `SameSite=Lax`, ephemeral RAM key storage | Prevents XSS cookie theft, cross-site request forgery, and client-side credential extraction. |
| **CSRF Protection** | `Flask-WTF` CSRF token verification | All state-changing POST requests require a valid cryptographic token. |

---

## 3. Cryptographic Architecture

```
                    +-----------------------+
                    |    User Interaction   |
                    +-----------------------+
                                |
                                | (Master Password)
                                v
               +----------------------------------+
               |  Authentication & Key Derivation  |
               +----------------------------------+
                     /                      \
        (Argon2id Hash)            (PBKDF2-HMAC-SHA256 + Salt)
                   /                          \
                  v                            v
      +---------------------+        +--------------------+
      | Verify Authenticity |        | Fernet AES-128 Key |
      | (Vault Configuration)|       | (In-Memory RAM Only)|
      +---------------------+        +--------------------+
                                               |
                                               v
                                     +--------------------+
                                     | Flask Application  |
                                     |  (Active Session)  |
                                     +--------------------+
                                        /              \
                          (Encrypt on Add)            (Decrypt on View)
                                      /                  \
                                     v                    v
                        +---------------------------------------+
                        |           SQLite Database             |
                        |      (Ciphertext Storage Only)        |
                        +---------------------------------------+
```

---

## 4. Why Fernet? (Explainability in Viva)

For a college mini-project, **Fernet** is the recommended authenticated encryption format because it bundles industry-standard primitives to prevent cryptographic implementation flaws:
1. **AES-128 in CBC mode** with PKCS7 padding for data confidentiality.
2. **HMAC using SHA-256** for message integrity and authenticity.
3. **128-bit Initialization Vector (IV)** uniquely generated for every encryption operation.
4. **Timestamp** to prevent replay attacks.

If an attacker modifies a single byte of ciphertext in SQLite, Fernet raises `InvalidToken`, refusing to return corrupted plaintext.

---

## 5. Hashing vs. Encryption: The Core Distinction

- **Hashing (One-Way):**  
  `Hash = Argon2id(Master Password)`  
  You cannot "reverse" or decrypt a hash. When the user logs in, the entered password is hashed and compared to verify identity.
- **Encryption (Two-Way):**  
  `Ciphertext = Fernet_Encrypt(Key, Plaintext)`  
  `Plaintext = Fernet_Decrypt(Key, Ciphertext)`  
  Requires a secret cryptographic key to reverse the ciphertext back to readable data.

---

## 6. Project Structure

```
securevault/
│
├── app.py                     # Main Flask web controller, routes, session management
├── requirements.txt           # Python dependencies (Flask, cryptography, argon2-cffi, Flask-WTF)
├── README.md                  # Complete documentation and viva guide
├── .gitignore                 # Excludes venv, sqlite db, cache, and sensitive files
├── inspect_db.py              # CLI tool to audit SQLite and demonstrate ciphertext storage
├── test_securevault.py        # Automated test suite verifying all 14 security scenarios
│
├── instance/                  # Local runtime directory
│   ├── securevault.db         # SQLite database file (created automatically)
│   └── .secret_key            # Persistent Flask session secret
│
├── templates/                 # Jinja2 HTML5 UI Templates
│   ├── base.html              # Cyber-themed navigation, status badges, CSRF meta
│   ├── setup.html             # First-launch master password setup
│   ├── login.html             # Unlock vault, brute-force countdown
│   ├── dashboard.html         # Vault records table, masked passwords, actions
│   ├── add_credential.html    # Add credential form with strength meter & generator
│   ├── edit_credential.html   # Edit and re-encrypt credential
│   └── generator.html         # Standalone CSPRNG password generator
│
├── static/
│   ├── css/
│   │   └── style.css          # Modern cybersecurity dark theme stylesheet
│   └── js/
│       └── main.js            # On-demand decryption, copy-to-clipboard, auto-lock
│
└── utils/                     # Modular Python Security Libraries
    ├── __init__.py
    ├── encryption.py          # Key derivation (PBKDF2) and Fernet AES encryption
    ├── security.py            # Argon2id hashing, brute-force rate limiter, ephemeral RAM keys
    ├── password_generator.py  # CSPRNG password generator (`secrets`) & strength meter
    └── db.py                  # Parameterized SQLite queries and CRUD logic
```

---

## 7. Windows VS Code Setup & Installation

Follow these exact steps in your VS Code terminal on Windows:

### Step 1: Open Terminal in Project Directory
In VS Code, press ``Ctrl + ` `` (Backtick) to open the integrated PowerShell terminal.

```powershell
cd C:\Users\Kirito\.gemini\antigravity-ide\scratch\securevault
```

### Step 2: Create Python Virtual Environment (If not already created)
```powershell
python -m venv venv
```

### Step 3: Activate the Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```
*(If PowerShell displays an execution policy error, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then activate again).*

### Step 4: Install Required Packages
```powershell
pip install -r requirements.txt
```

### Step 5: Run the Application
```powershell
python app.py
```

### Step 6: Open in Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 8. College Viva Demonstration Procedure

Follow this 5-minute walkthrough during your project demonstration:

1. **First-Time Setup Demonstration:**
   - Open `http://127.0.0.1:5000`. The application detects an empty database and redirects to `/setup`.
   - Create a master password (e.g., `MasterKey@2026!`). Show the live **Password Strength Meter**.
   - Explain to the examiner: *"Argon2id hashes this password with 64MB memory cost, and a 16-byte random salt is generated."*

2. **Add Credential & Password Generator Demonstration:**
   - Click **Add Password**.
   - Click **Generate Strong Password**. Show that it uses Python's `secrets` module (CSPRNG) rather than `random`.
   - Enter `GitHub` as website, `student@college.edu` as username, and save.
   - Explain: *"Before saving to SQLite, Fernet encrypts the plaintext password into a base64 ciphertext token."*

3. **Database Inspection Proof (The "Killer" Viva Step):**
   - Open a second terminal window and run:
     ```powershell
     python inspect_db.py
     ```
   - Show the examiner the terminal output:
     - Notice `master_hash` is an Argon2id string. The master password itself is **nowhere** in the file.
     - Notice `encrypted_password` is `gAAAAA...` (Fernet token). **Zero plaintext is stored in the database.**

4. **On-Demand Decryption & Clipboard Security:**
   - In the web dashboard, show that passwords default to `••••••••••••`.
   - Click **View**: Explain that a secure POST request verifies the active session and decrypts the password into UI, auto-hiding after 30 seconds.
   - Click **Copy**: Copies the password to the clipboard and automatically clears it after 30 seconds.

5. **Brute-Force Rate Limiting Demonstration:**
   - Click **Lock Vault**.
   - Deliberately enter an incorrect master password 5 times in a row.
   - Show that the rate limiter activates: *"Rate limit exceeded: login locked for 60 seconds."*

6. **Persistence Demonstration Across Restarts:**
   - Stop Flask in the terminal with `Ctrl + C`.
   - Start it again with `python app.py`.
   - Enter the master password.
   - Show that all previously saved passwords can still be decrypted correctly because the KDF derives the identical key from the password + stored salt.

---

## 9. Top 10 CNS Viva Questions & Answers

### Q1: Why didn't you use Python's built-in `random` module for generating passwords?
> **Answer:** Python's standard `random` module uses the Mersenne Twister PRNG, which is completely deterministic. If an attacker observes 624 generated numbers, they can predict all future and past outputs. SecureVault uses the `secrets` module, which draws cryptographically secure entropy directly from the OS kernel (Windows `BCryptGenRandom`).

### Q2: Why is the master password hashed using Argon2id instead of SHA-256 or MD5?
> **Answer:** MD5 and SHA-256 are fast hash functions designed for message integrity, making them vulnerable to modern GPUs and ASICs that can compute billions of hashes per second. Argon2id won the Password Hashing Competition (PHC) because it is **memory-hard**—it requires 64 MB of RAM per hash evaluation, neutralizing GPU cracking arrays.

### Q3: What is the difference between encryption and hashing?
> **Answer:** Hashing is a **one-way function** (cannot be decrypted), used here to verify the master password. Encryption is a **two-way function** with a secret key (can be decrypted), used here to protect stored website credentials.

### Q4: Where is the encryption key stored?
> **Answer:** The encryption key is **never written to disk or the database**. It is derived dynamically from the master password and stored salt using PBKDF2. It exists solely in volatile server RAM while the session is unlocked, and is destroyed when locked or after 5 minutes of inactivity.

### Q5: What is the purpose of the salt in the KDF?
> **Answer:** A cryptographic salt is a unique, random 16-byte value generated per vault. It ensures that two users with identical master passwords will produce completely different hashes and encryption keys, defeating precomputed rainbow tables.

### Q6: How does Fernet prevent ciphertext tampering?
> **Answer:** Fernet utilizes **Authenticated Encryption**. It appends an HMAC-SHA256 signature to the AES-CBC ciphertext. Before decrypting, it verifies the HMAC using constant-time comparison. If an attacker alters any byte in the database, the signature check fails and an `InvalidToken` error is raised.

### Q7: Why do we use parameterized SQL queries (`?`)?
> **Answer:** Parameterized queries send SQL code and user input separately to the database engine. This prevents SQL Injection (SQLi) attacks because user inputs can never be interpreted as executable SQL instructions.

### Q8: How does the application protect against Cross-Site Request Forgery (CSRF)?
> **Answer:** Using `Flask-WTF`, every state-changing form and AJAX request includes a unique, cryptographically signed CSRF token tied to the user's session. Requests missing or with mismatched tokens are immediately rejected.

### Q9: Why is the `HTTPOnly` flag enabled on cookies?
> **Answer:** `HTTPOnly` prevents client-side scripts (such as malicious JavaScript injected via Cross-Site Scripting, or XSS) from reading the session cookie via `document.cookie`.

### Q10: How does the auto-lock feature work?
> **Answer:** The server tracks a `last_active` timestamp for each unlocked session token. When an incoming request arrives, if `time.time() - last_active > 300` seconds (5 minutes), the server immediately purges the derived Fernet key from memory and redirects the user to the login page.

---

## 10. Security Limitations & Disclaimer

This project is designed for **academic, educational, and demonstration purposes** in Computer Engineering / Cybersecurity courses. While it follows industry-standard cryptographic practices (Argon2id, PBKDF2, Fernet authenticated encryption), commercial password managers (such as Bitwarden or 1Password) incorporate additional layers such as client-side zero-knowledge WebAssembly encryption, encrypted RAM enclaves, OS keyring integrations, and multi-factor hardware keys (FIDO2/WebAuthn).
