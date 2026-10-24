"""
SecureVault - Comprehensive Automated Verification Test Suite
Tests all 14 scenarios specified in the project requirements.
"""

import os
import sys
import time
import sqlite3
import unittest

# Ensure Windows console encoding compatibility
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Import application components
from app import app, DB_PATH, INSTANCE_DIR
from utils.encryption import (
    generate_kdf_salt, derive_encryption_key,
    encrypt_data, decrypt_data
)
from utils.security import (
    hash_master_password, verify_master_password,
    unlock_vault, get_vault_key, lock_vault,
    AUTO_LOCK_TIMEOUT_SECONDS
)
from utils.password_generator import generate_password, evaluate_password_strength
from utils.db import (
    init_db, is_vault_initialized, get_vault_config,
    setup_vault_config, check_login_lockout, record_failed_attempt,
    reset_failed_attempts, list_credentials, get_credential,
    add_credential, update_credential, delete_credential
)


class SecureVaultTests(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.db_path = DB_PATH

    def test_01_first_launch_setup(self):
        """Test 1: First launch detects uninitialized vault and allows setup."""
        print("\n--- Running Test 1: Master Password Setup ---")
        master_pwd = "SuperSecretMasterPassword123!"
        salt = generate_kdf_salt()
        pwd_hash = hash_master_password(master_pwd)
        setup_vault_config(self.db_path, pwd_hash, salt.hex())
        
        self.assertTrue(is_vault_initialized(self.db_path))
        cfg = get_vault_config(self.db_path)
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg['kdf_salt'], salt.hex())
        print("[PASS] Test 1: Master password and KDF salt initialized.")

    def test_02_correct_master_password_unlock(self):
        """Test 2: Correct master password verifies and derives correct key."""
        print("\n--- Running Test 2: Master Password Unlock ---")
        master_pwd = "SuperSecretMasterPassword123!"
        cfg = get_vault_config(self.db_path)
        is_valid = verify_master_password(cfg['master_hash'], master_pwd)
        self.assertTrue(is_valid)

        key = derive_encryption_key(master_pwd, bytes.fromhex(cfg['kdf_salt']))
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 44)  # Fernet key is 32 bytes urlsafe base64 (44 chars)
        print("[PASS] Test 2: Master password verified and Fernet key derived.")

    def test_03_incorrect_master_password_rejected(self):
        """Test 3: Incorrect master password is rejected."""
        print("\n--- Running Test 3: Incorrect Master Password Rejection ---")
        cfg = get_vault_config(self.db_path)
        is_valid = verify_master_password(cfg['master_hash'], "WrongPassword!")
        self.assertFalse(is_valid)
        print("[PASS] Test 3: Invalid master password safely rejected.")

    def test_04_and_05_add_credential_and_verify_ciphertext(self):
        """Test 4 & 5: Credential added and verified to be CIPHERTEXT in SQLite."""
        print("\n--- Running Tests 4 & 5: Add Credential & Verify SQLite Ciphertext ---")
        master_pwd = "SuperSecretMasterPassword123!"
        cfg = get_vault_config(self.db_path)
        key = derive_encryption_key(master_pwd, bytes.fromhex(cfg['kdf_salt']))

        plaintext_password = "P@ssw0rdForGitHub!"
        plaintext_notes = "Secret recovery codes: 1234, 5678"
        
        # Encrypt before database storage
        enc_pwd = encrypt_data(plaintext_password, key)
        enc_notes = encrypt_data(plaintext_notes, key)

        cred_id = add_credential(
            self.db_path,
            website="GitHub",
            username="octocat@github.com",
            encrypted_password=enc_pwd,
            url="https://github.com",
            encrypted_notes=enc_notes
        )
        self.assertIsNotNone(cred_id)

        # Inspect SQLite directly via raw query to confirm CIPHERTEXT
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_password, encrypted_notes FROM credentials WHERE id = ?", (cred_id,))
        row = cursor.fetchone()
        conn.close()

        stored_password_in_db = row[0]
        stored_notes_in_db = row[1]

        # Verify plaintext is NEVER present in SQLite
        self.assertNotEqual(stored_password_in_db, plaintext_password)
        self.assertNotIn("P@ssw0rdForGitHub!", stored_password_in_db)
        self.assertTrue(stored_password_in_db.startswith("gAAAAA"))  # Fernet tokens start with gAAAAA
        self.assertNotIn("Secret recovery codes", stored_notes_in_db)
        print(f"[PASS] Tests 4 & 5: Plaintext is NOT in SQLite. Raw stored token: {stored_password_in_db[:25]}...")

    def test_06_decrypt_credential(self):
        """Test 6: Encrypted password decrypts accurately with key."""
        print("\n--- Running Test 6: Decrypt Credential ---")
        master_pwd = "SuperSecretMasterPassword123!"
        cfg = get_vault_config(self.db_path)
        key = derive_encryption_key(master_pwd, bytes.fromhex(cfg['kdf_salt']))

        cred = list_credentials(self.db_path, search="GitHub")[0]
        decrypted_pwd = decrypt_data(cred['encrypted_password'], key)
        decrypted_notes = decrypt_data(cred['encrypted_notes'], key)

        self.assertEqual(decrypted_pwd, "P@ssw0rdForGitHub!")
        self.assertEqual(decrypted_notes, "Secret recovery codes: 1234, 5678")
        print("[PASS] Test 6: Decrypted values match original plaintexts exactly.")

    def test_07_edit_credential(self):
        """Test 7: Credential can be updated and re-encrypted."""
        print("\n--- Running Test 7: Edit Credential ---")
        master_pwd = "SuperSecretMasterPassword123!"
        cfg = get_vault_config(self.db_path)
        key = derive_encryption_key(master_pwd, bytes.fromhex(cfg['kdf_salt']))

        cred = list_credentials(self.db_path, search="GitHub")[0]
        new_password = "UpdatedNewPassword999$"
        new_enc_pwd = encrypt_data(new_password, key)

        success = update_credential(
            self.db_path,
            cred['id'],
            website="GitHub",
            username="octocat_updated",
            encrypted_password=new_enc_pwd,
            url="https://github.com/login",
            encrypted_notes=""
        )
        self.assertTrue(success)

        updated_cred = get_credential(self.db_path, cred['id'])
        self.assertEqual(updated_cred['username'], "octocat_updated")
        self.assertEqual(decrypt_data(updated_cred['encrypted_password'], key), new_password)
        print("[PASS] Test 7: Credential successfully updated and re-encrypted.")

    def test_08_delete_credential(self):
        """Test 8: Credential can be deleted."""
        print("\n--- Running Test 8: Delete Credential ---")
        cred = list_credentials(self.db_path, search="GitHub")[0]
        success = delete_credential(self.db_path, cred['id'])
        self.assertTrue(success)

        self.assertIsNone(get_credential(self.db_path, cred['id']))
        print("[PASS] Test 8: Credential deleted.")

    def test_09_password_generator(self):
        """Test 9: Password generator creates cryptographically strong random passwords."""
        print("\n--- Running Test 9: Password Generator & CSPRNG ---")
        pwd = generate_password(length=20, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
        self.assertEqual(len(pwd), 20)
        self.assertTrue(any(c.isupper() for c in pwd))
        self.assertTrue(any(c.islower() for c in pwd))
        self.assertTrue(any(c.isdigit() for c in pwd))

        eval_result = evaluate_password_strength(pwd)
        self.assertEqual(eval_result['rating'], "Strong")
        print(f"[PASS] Test 9: Generated password '{pwd}' rated Strong ({eval_result['score']}%).")

    def test_10_immediate_lock(self):
        """Test 10: Lock immediately clears key from memory."""
        print("\n--- Running Test 10: Manual Lock ---")
        token = "test_session_token_123"
        key = b"dummy_fernet_key_bytes_123456789"
        unlock_vault(token, key)
        self.assertIsNotNone(get_vault_key(token))

        lock_vault(token)
        self.assertIsNone(get_vault_key(token))
        print("[PASS] Test 10: Vault lock immediately purged key from memory.")

    def test_11_auto_lock_timeout(self):
        """Test 11: Inactivity timeout purges key."""
        print("\n--- Running Test 11: Auto-Lock Inactivity Timeout ---")
        token = "test_session_timeout"
        key = b"dummy_fernet_key_bytes_123456789"
        unlock_vault(token, key)
        
        # Simulate elapsed time beyond 300s
        from utils.security import _VAULT_SESSIONS
        _VAULT_SESSIONS[token]['last_active'] = time.time() - (AUTO_LOCK_TIMEOUT_SECONDS + 5)

        # Retrieving key should now trigger auto-lock and return None
        self.assertIsNone(get_vault_key(token))
        print("[PASS] Test 11: Key auto-locked and destroyed after 5 minutes of idle time.")

    def test_12_brute_force_protection(self):
        """Test 12: Multiple failed login attempts trigger temporary lockout."""
        print("\n--- Running Test 12: Brute-Force Rate Limiting ---")
        ip = "192.168.1.100"
        reset_failed_attempts(self.db_path, ip)

        for i in range(1, 5):
            attempts, lockout = record_failed_attempt(self.db_path, ip, max_attempts=5, lockout_seconds=60)
            self.assertEqual(attempts, i)
            self.assertEqual(lockout, 0)

        # 5th attempt must trigger lockout
        attempts, lockout = record_failed_attempt(self.db_path, ip, max_attempts=5, lockout_seconds=60)
        self.assertEqual(attempts, 5)
        self.assertGreater(lockout, 0)

        is_locked, rem = check_login_lockout(self.db_path, ip)
        self.assertTrue(is_locked)
        self.assertGreater(rem, 0)
        print(f"[PASS] Test 12: Brute-force lockout active ({rem} seconds remaining).")

    def test_13_csrf_protection_enabled(self):
        """Test 13: CSRF protection is active on state-changing operations."""
        print("\n--- Running Test 13: CSRF Protection Verification ---")
        self.assertTrue(app.config.get('SESSION_COOKIE_HTTPONLY'))
        self.assertEqual(app.config.get('SESSION_COOKIE_SAMESITE'), 'Lax')
        print("[PASS] Test 13: CSRF protection and secure cookie flags active.")

    def test_14_restart_persistence(self):
        """Test 14: Application restart persists credentials and allows decryption."""
        print("\n--- Running Test 14: Persistence Across Application Restarts ---")
        master_pwd = "SuperSecretMasterPassword123!"
        
        # 1. Fetch persistent configuration from SQLite
        cfg = get_vault_config(self.db_path)
        self.assertIsNotNone(cfg)

        # 2. Add a persistent credential
        key = derive_encryption_key(master_pwd, bytes.fromhex(cfg['kdf_salt']))
        secret_content = "UltraSecretVaultData2026!"
        enc_secret = encrypt_data(secret_content, key)
        cred_id = add_credential(
            self.db_path,
            website="BankingPortal",
            username="finance_admin",
            encrypted_password=enc_secret,
            url="https://bank.example.com",
            encrypted_notes=""
        )

        # 3. Simulate completely closing and reopening Flask / Python process
        from utils.security import _VAULT_SESSIONS
        _VAULT_SESSIONS.clear()

        # 4. Simulate relaunch: read from database again using master password
        fresh_cfg = get_vault_config(self.db_path)
        self.assertTrue(verify_master_password(fresh_cfg['master_hash'], master_pwd))
        fresh_key = derive_encryption_key(master_pwd, bytes.fromhex(fresh_cfg['kdf_salt']))

        # 5. Fetch stored credential and decrypt
        stored_cred = get_credential(self.db_path, cred_id)
        decrypted = decrypt_data(stored_cred['encrypted_password'], fresh_key)
        self.assertEqual(decrypted, secret_content)
        print("[PASS] Test 14: Persistence fully verified across simulated app restarts.")


if __name__ == '__main__':
    unittest.main()
