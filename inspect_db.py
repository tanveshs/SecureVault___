"""
SecureVault - Database Inspector Utility for College Viva Demo
Run this script in terminal to inspect what is stored inside SQLite:
    python inspect_db.py
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'securevault.db')

def inspect():
    if not os.path.exists(DB_PATH):
        print("[!] No database file found at instance/securevault.db. Run the app first.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print("\n" + "=" * 75)
    print("           SECUREVAULT DATABASE AUDIT / VIVA INSPECTION")
    print("=" * 75)

    # 1. Vault Config
    print("\n[TABLE: vault_config] (Master Password Verification & KDF Salt)")
    print("-" * 75)
    try:
        cursor.execute("SELECT id, master_hash, kdf_salt, created_at FROM vault_config")
        cfg = cursor.fetchone()
        if cfg:
            print(f"ID:          {cfg['id']}")
            print(f"Master Hash: {cfg['master_hash'][:40]}... (Argon2id Memory-Hard Hash)")
            print(f"KDF Salt:    {cfg['kdf_salt']} (16-byte Random Cryptographic Salt)")
            print(f"Created At:  {cfg['created_at']}")
            print("\n>> VIVA NOTE: Notice the master password itself is NOT stored anywhere!")
        else:
            print("Vault is not initialized yet. Run app.py and complete setup.")
    except Exception as e:
        print(f"Error reading vault_config: {e}")

    # 2. Credentials Table
    print("\n" + "-" * 75)
    print("[TABLE: credentials] (Stored Vault Records)")
    print("-" * 75)
    try:
        cursor.execute("SELECT id, website, username, encrypted_password, url, encrypted_notes FROM credentials")
        rows = cursor.fetchall()
        if not rows:
            print("No credentials saved yet.")
        else:
            for row in rows:
                print(f"\n[Credential #{row['id']}]")
                print(f"  Website:            {row['website']}")
                print(f"  Username:           {row['username']}")
                print(f"  Encrypted Password: {row['encrypted_password']}")
                print(f"  URL:                {row['url'] or 'N/A'}")
                print(f"  Encrypted Notes:    {row['encrypted_notes'] or 'None'}")
            
            print("\n" + "=" * 75)
            print(">> CONFIDENTIALITY PROOF:")
            print("   Notice that passwords and notes are stored strictly as Fernet tokens")
            print("   (AES-128-CBC + HMAC-SHA256), NEVER as plaintext strings!")
            print("=" * 75 + "\n")
    except Exception as e:
        print(f"Error reading credentials: {e}")

    conn.close()

if __name__ == '__main__':
    inspect()
