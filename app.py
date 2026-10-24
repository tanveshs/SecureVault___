"""
SecureVault - Encrypted Password Manager
Main Flask Application

CYBERSECURITY CONCEPTS DEMONSTRATED:
1. Zero-Knowledge Architecture (Local):
   - The master password is never saved in plaintext or database.
   - All credentials are encrypted using Fernet (AES-128-CBC + HMAC-SHA256).
   - Plaintext passwords exist ONLY ephemerally in RAM when decrypted for immediate view/copy.
2. Defense-in-Depth:
   - Argon2id for master password hashing (memory-hard, GPU-resistant).
   - PBKDF2-HMAC-SHA256 (600,000 iterations) with 16-byte cryptographically random salt for KDF.
   - Brute-force rate limiting with temporary IP lockout.
   - CSRF protection across all state-changing endpoints (Flask-WTF).
   - HTTPOnly and SameSite cookie security flags.
   - Auto-lock after 5 minutes of inactivity.
"""

import os
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, abort
)
from flask_wtf.csrf import CSRFProtect, generate_csrf

from utils.encryption import (
    generate_kdf_salt, derive_encryption_key,
    encrypt_data, decrypt_data
)
from utils.security import (
    hash_master_password, verify_master_password,
    unlock_vault, get_vault_key, lock_vault,
    get_remaining_idle_time, touch_vault
)
from utils.password_generator import generate_password, evaluate_password_strength
from utils.db import (
    init_db, is_vault_initialized, get_vault_config, setup_vault_config,
    check_login_lockout, record_failed_attempt, reset_failed_attempts,
    list_credentials, get_credential, add_credential,
    update_credential, delete_credential
)

# ----------------------------------------------------------------------------
# Application Initialization & Security Configuration
# ----------------------------------------------------------------------------

app = Flask(__name__)

# Base Paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'securevault.db')
SECRET_KEY_PATH = os.path.join(INSTANCE_DIR, '.secret_key')

os.makedirs(INSTANCE_DIR, exist_ok=True)

# Persistent Flask Secret Key (avoids session invalidation on server restart without hardcoding)
if not os.path.exists(SECRET_KEY_PATH):
    with open(SECRET_KEY_PATH, 'wb') as f:
        f.write(secrets.token_bytes(32))
with open(SECRET_KEY_PATH, 'rb') as f:
    app.secret_key = f.read()

# Flask Session Security Configuration
# In production with HTTPS, set SESSION_COOKIE_SECURE = True
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Mitigates XSS-based session theft
    SESSION_COOKIE_SAMESITE='Lax',  # Protects against CSRF via cross-site requests
    SESSION_COOKIE_SECURE=False,    # Set to True when deploying behind HTTPS/TLS
    PERMANENT_SESSION_LIFETIME=1800 # 30 minutes absolute session ceiling
)

# Enable CSRF Protection for all forms and AJAX requests
csrf = CSRFProtect(app)


# Initialize Database automatically on startup
with app.app_context():
    init_db(DB_PATH)


# Context processor to make CSRF token and auto-lock state accessible in Jinja templates
@app.context_processor
def inject_security_context():
    session_token = session.get('session_token')
    is_unlocked = False
    remaining_idle = 0
    if session_token:
        key = get_vault_key(session_token)
        if key is not None:
            is_unlocked = True
            remaining_idle = get_remaining_idle_time(session_token)

    return {
        'csrf_token': generate_csrf,
        'is_vault_unlocked': is_unlocked,
        'vault_remaining_idle': remaining_idle
    }


# ----------------------------------------------------------------------------
# Access Control Decorator
# ----------------------------------------------------------------------------

def login_required(f):
    """
    Decorator requiring an authenticated and actively unlocked vault session.
    If session expired (5 min inactivity) or key was purged, redirects to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        if not session_token:
            flash("Please unlock your vault to continue.", "warning")
            return redirect(url_for('login'))

        # Verifies key presence and enforces 5-minute auto-lock timeout
        vault_key = get_vault_key(session_token)
        if vault_key is None:
            # Auto-lock triggered or never unlocked
            session.clear()
            flash("Vault locked due to inactivity or invalid session. Please enter master password.", "warning")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function


# ----------------------------------------------------------------------------
# Request Interceptor (First-Run Setup Detection)
# ----------------------------------------------------------------------------

@app.before_request
def check_first_run():
    """
    Ensures users configure a master password before accessing any vault routes.
    """
    # Allow static assets and setup page without redirect
    if request.endpoint in ['static', 'setup']:
        return

    # Check if vault has been initialized
    if not is_vault_initialized(DB_PATH):
        return redirect(url_for('setup'))


# ----------------------------------------------------------------------------
# Authentication & Setup Routes
# ----------------------------------------------------------------------------

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """
    First-time Master Password Setup.
    Demonstrates:
    - Master password hashing with Argon2id.
    - Unique KDF salt generation (16 bytes random).
    - Derivation of the primary vault encryption key.
    """
    if is_vault_initialized(DB_PATH):
        flash("Vault is already initialized. Please enter your master password.", "info")
        return redirect(url_for('login'))

    if request.method == 'POST':
        master_password = request.form.get('master_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not master_password or not confirm_password:
            flash("Master password cannot be empty.", "danger")
            return render_template('setup.html')

        if master_password != confirm_password:
            flash("Master passwords do not match.", "danger")
            return render_template('setup.html')

        if len(master_password) < 8:
            flash("For security, master password must be at least 8 characters long.", "danger")
            return render_template('setup.html')

        # 1. Generate unique 16-byte KDF salt for key derivation
        kdf_salt_bytes = generate_kdf_salt()
        kdf_salt_hex = kdf_salt_bytes.hex()

        # 2. Hash master password with Argon2id (Never store plaintext password!)
        master_hash = hash_master_password(master_password)

        # 3. Store master hash and KDF salt in SQLite
        setup_vault_config(DB_PATH, master_hash, kdf_salt_hex)

        # 4. Derive encryption key and initialize user session
        fernet_key = derive_encryption_key(master_password, kdf_salt_bytes)
        session_token = secrets.token_hex(32)
        session['session_token'] = session_token
        unlock_vault(session_token, fernet_key)

        flash("Master password established! Your secure vault is now unlocked.", "success")
        return redirect(url_for('dashboard'))

    return render_template('setup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Vault Unlock / Authentication Page.
    Demonstrates:
    - Brute-force rate limiting (5 attempts -> 60s lockout).
    - Argon2id password hash verification.
    - Symmetric encryption key derivation from master password + stored salt.
    """
    # If already unlocked, redirect to dashboard
    session_token = session.get('session_token')
    if session_token and get_vault_key(session_token) is not None:
        return redirect(url_for('dashboard'))

    client_ip = request.remote_addr or '127.0.0.1'

    # Check for active brute-force lockout
    is_locked, remaining_seconds = check_login_lockout(DB_PATH, client_ip)
    if is_locked:
        flash(f"Security Alert: Too many failed attempts. Login locked for {remaining_seconds} seconds.", "danger")
        return render_template('login.html', is_locked=True, remaining_seconds=remaining_seconds)

    if request.method == 'POST':
        master_password = request.form.get('master_password', '')

        vault_cfg = get_vault_config(DB_PATH)
        if not vault_cfg:
            return redirect(url_for('setup'))

        # Verify candidate master password using Argon2id
        is_valid = verify_master_password(vault_cfg['master_hash'], master_password)

        if not is_valid:
            # Record failed attempt and compute lockout if threshold reached
            attempts, lockout_remaining = record_failed_attempt(DB_PATH, client_ip)
            if lockout_remaining > 0:
                flash(f"Incorrect master password. Security threshold reached: locked for {lockout_remaining} seconds.", "danger")
                return render_template('login.html', is_locked=True, remaining_seconds=lockout_remaining)
            else:
                remaining_attempts = 5 - attempts
                flash(f"Incorrect master password. {remaining_attempts} attempt(s) remaining before lockout.", "danger")
                return render_template('login.html', is_locked=False)

        # Authentication succeeded: reset failed attempts
        reset_failed_attempts(DB_PATH, client_ip)

        # Derive Fernet key using stored KDF salt
        kdf_salt_bytes = bytes.fromhex(vault_cfg['kdf_salt'])
        fernet_key = derive_encryption_key(master_password, kdf_salt_bytes)

        # Generate fresh session token and store key in RAM
        session_token = secrets.token_hex(32)
        session['session_token'] = session_token
        unlock_vault(session_token, fernet_key)

        flash("Vault unlocked successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html', is_locked=False)


@app.route('/lock', methods=['POST'])
def lock():
    """
    Immediately locks the vault and purges derived encryption key from memory.
    """
    session_token = session.get('session_token')
    if session_token:
        lock_vault(session_token)
    session.clear()
    flash("Vault has been securely locked. Key purged from memory.", "info")
    return redirect(url_for('login'))


@app.route('/logout', methods=['POST'])
def logout():
    """
    Alias for locking vault and ending session.
    """
    return lock()


# ----------------------------------------------------------------------------
# Vault Dashboard & Credential Management Routes
# ----------------------------------------------------------------------------

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Password Vault Dashboard.
    Lists all credentials with passwords securely masked (••••••••••••).
    """
    search_query = request.args.get('q', '').strip()
    credentials_list = list_credentials(DB_PATH, search=search_query if search_query else None)
    return render_template(
        'dashboard.html',
        credentials=credentials_list,
        search_query=search_query,
        count=len(credentials_list)
    )


@app.route('/credentials/add', methods=['GET', 'POST'])
@login_required
def add():
    """
    Add new credential to vault.
    Plaintext password & notes are encrypted using Fernet BEFORE inserting into SQLite.
    """
    if request.method == 'POST':
        website = request.form.get('website', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        url = request.form.get('url', '').strip()
        notes = request.form.get('notes', '').strip()

        if not website or not username or not password:
            flash("Website, username, and password are required.", "danger")
            return render_template('add_credential.html')

        # Retrieve derived encryption key for current session
        session_token = session.get('session_token')
        fernet_key = get_vault_key(session_token)
        if not fernet_key:
            return redirect(url_for('login'))

        # Encrypt sensitive fields: Plaintext -> Ciphertext
        encrypted_password = encrypt_data(password, fernet_key)
        encrypted_notes = encrypt_data(notes, fernet_key) if notes else ""

        # Insert ciphertext into SQLite
        add_credential(DB_PATH, website, username, encrypted_password, url, encrypted_notes)

        flash(f"Credentials for '{website}' encrypted and saved securely.", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_credential.html')


@app.route('/credentials/<int:credential_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(credential_id: int):
    """
    Edit existing credential.
    Decrypts stored ciphertext for editing, then re-encrypts upon save.
    """
    session_token = session.get('session_token')
    fernet_key = get_vault_key(session_token)
    if not fernet_key:
        return redirect(url_for('login'))

    cred = get_credential(DB_PATH, credential_id)
    if not cred:
        flash("Credential not found.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        website = request.form.get('website', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        url = request.form.get('url', '').strip()
        notes = request.form.get('notes', '').strip()

        if not website or not username or not password:
            flash("Website, username, and password are required.", "danger")
            return render_template('edit_credential.html', cred=cred)

        # Re-encrypt updated password and notes
        encrypted_password = encrypt_data(password, fernet_key)
        encrypted_notes = encrypt_data(notes, fernet_key) if notes else ""

        update_credential(DB_PATH, credential_id, website, username, encrypted_password, url, encrypted_notes)

        flash(f"Credentials for '{website}' updated and re-encrypted.", "success")
        return redirect(url_for('dashboard'))

    # Decrypt credential values for pre-filling edit form
    try:
        decrypted_password = decrypt_data(cred['encrypted_password'], fernet_key)
        decrypted_notes = decrypt_data(cred['encrypted_notes'], fernet_key) if cred['encrypted_notes'] else ""
    except ValueError as e:
        flash(f"Decryption error: {e}", "danger")
        return redirect(url_for('dashboard'))

    return render_template(
        'edit_credential.html',
        cred=cred,
        decrypted_password=decrypted_password,
        decrypted_notes=decrypted_notes
    )


@app.route('/credentials/<int:credential_id>/delete', methods=['POST'])
@login_required
def delete(credential_id: int):
    """
    Secure deletion of credential via POST request (prevents CSRF and accidental GET deletion).
    """
    success = delete_credential(DB_PATH, credential_id)
    if success:
        flash("Credential successfully deleted from vault.", "info")
    else:
        flash("Could not delete credential: not found.", "warning")
    return redirect(url_for('dashboard'))


# ----------------------------------------------------------------------------
# Secure View & Decryption API (AJAX / Ephemeral Decryption)
# ----------------------------------------------------------------------------

@app.route('/credentials/<int:credential_id>/view', methods=['POST'])
@login_required
def view_credential(credential_id: int):
    """
    Decrypts and returns credential password and notes strictly on demand.
    Protected by CSRF token and active session verification.
    """
    session_token = session.get('session_token')
    fernet_key = get_vault_key(session_token)
    if not fernet_key:
        return jsonify({'success': False, 'error': 'Session expired or vault locked'}), 401

    cred = get_credential(DB_PATH, credential_id)
    if not cred:
        return jsonify({'success': False, 'error': 'Credential not found'}), 404

    try:
        decrypted_password = decrypt_data(cred['encrypted_password'], fernet_key)
        decrypted_notes = decrypt_data(cred['encrypted_notes'], fernet_key) if cred['encrypted_notes'] else ""
        return jsonify({
            'success': True,
            'password': decrypted_password,
            'notes': decrypted_notes
        })
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ----------------------------------------------------------------------------
# Password Generator & Evaluation Utilities
# ----------------------------------------------------------------------------

@app.route('/generator')
@login_required
def generator_page():
    """
    Standalone Password Generator page.
    """
    return render_template('generator.html')


@app.route('/api/generate-password', methods=['POST'])
@login_required
def api_generate_password():
    """
    Generates a cryptographically secure random password using Python's `secrets` module.
    """
    data = request.get_json(silent=True) or request.form
    length = int(data.get('length', 16))
    use_upper = data.get('upper', True) in [True, 'true', 'on', '1']
    use_lower = data.get('lower', True) in [True, 'true', 'on', '1']
    use_digits = data.get('digits', True) in [True, 'true', 'on', '1']
    use_symbols = data.get('symbols', True) in [True, 'true', 'on', '1']

    generated = generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols
    )
    strength = evaluate_password_strength(generated)

    return jsonify({
        'success': True,
        'password': generated,
        'strength': strength
    })


@app.route('/api/evaluate-strength', methods=['POST'])
def api_evaluate_strength():
    """
    Evaluates password strength metrics.
    """
    data = request.get_json(silent=True) or request.form
    password = data.get('password', '')
    result = evaluate_password_strength(password)
    return jsonify(result)


@app.route('/api/session-status', methods=['GET'])
def api_session_status():
    """
    Returns auto-lock countdown timer status for frontend synchronization.
    """
    session_token = session.get('session_token')
    if not session_token:
        return jsonify({'unlocked': False, 'remaining_seconds': 0})

    remaining = get_remaining_idle_time(session_token)
    return jsonify({
        'unlocked': remaining > 0,
        'remaining_seconds': remaining
    })


# ----------------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 60)
    print(" SecureVault: Encrypted Password Manager")
    print(" Local Server starting at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5000, debug=True)
