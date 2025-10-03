# password_suite.py - A Single-File Password Security Suite

import os
import json
import base64
import string
import secrets
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

# --- Configuration & File Paths ---
KEY_FILE = 'master_key.key'
VAULT_FILE = 'password_vault.json'
SALT_SIZE = 16

# --- CORE FUNCTIONS (Encryption/Decryption/Key Derivation) ---

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from the master password and salt."""
    password_bytes = master_password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def generate_key_materials(master_password: str) -> tuple[bytes, bytes]:
    """Generates the salt and the initial Fernet key."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    return key, salt

def load_salt() -> bytes | None:
    """Loads the salt from the key file."""
    try:
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None

def save_key_materials(salt: bytes):
    """Saves the salt to the key file for consistent key regeneration."""
    try:
        with open(KEY_FILE, 'wb') as f:
            f.write(salt)
    except IOError as e:
        print(f"Error saving key materials: {e}")

def encrypt_data(data: str, key: bytes) -> str:
    """Encrypts a string using Fernet."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(token: str, key: bytes) -> str | None:
    """Decrypts a Fernet token. Returns None on failure."""
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(token.encode())
        return decrypted_data.decode()
    except InvalidToken:
        return None
    except Exception:
        return None 

# --- VAULT MANAGEMENT ---

def load_vault(key: bytes) -> dict[str, dict]:
    """Loads and attempts to decrypt the password vault."""
    if not os.path.exists(VAULT_FILE):
        return {}
    
    with open(VAULT_FILE, 'r') as f:
        try:
            encrypted_vault = json.load(f)
        except json.JSONDecodeError:
            return {}
    
    decrypted_vault = {}
    
    for site, data in encrypted_vault.items():
        decrypted_pwd = decrypt_data(data.get('password', ''), key)
        decrypted_user = decrypt_data(data.get('username', ''), key)
        
        if decrypted_pwd and decrypted_user:
            decrypted_vault[site] = {
                'username': decrypted_user,
                'password': decrypted_pwd
            }
            
    return decrypted_vault

def save_vault(decrypted_vault: dict, key: bytes):
    """Encrypts and saves the password vault."""
    encrypted_vault = {}
    
    for site, data in decrypted_vault.items():
        if 'username' in data and 'password' in data:
             encrypted_vault[site] = {
                'username': encrypt_data(data['username'], key),
                'password': encrypt_data(data['password'], key)
            }

    with open(VAULT_FILE, 'w') as f:
        json.dump(encrypted_vault, f, indent=4)

# --- PASSWORD STRENGTH CHECKER ---

def check_strength(password: str) -> tuple[str, str]:
    """Scores a password and returns a rating and feedback."""
    score = 0
    feedback = []
    
    length = len(password)
    if length < 10:
        feedback.append(f"Length must be at least 10 characters (currently {length}).")
    elif length >= 12:
        score += 20
    
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    
    if has_upper: score += 15
    else: feedback.append("Needs uppercase letters.")
        
    if has_lower: score += 15
    else: feedback.append("Needs lowercase letters.")
        
    if has_digit: score += 15
    else: feedback.append("Needs numbers.")
        
    if has_symbol: score += 15
    else: feedback.append("Needs special characters/symbols.")

    if any(password.lower().count(seq) > 0 for seq in ["123", "abc", "qwe", "password"]):
        score -= 10
        feedback.append("Avoid simple sequences (e.g., '123', 'abc', or common words).")
        
    MAX_SCORE = 80
    if score >= 70 and not feedback:
        rating = "⭐ Excellent"
    elif score >= 50:
        rating = "👍 Strong"
    elif score >= 30:
        rating = "⚠️ Fair"
    else:
        rating = "🚨 Weak"

    if rating in ("⚠️ Fair", "🚨 Weak"):
        feedback_str = "\n".join(f"- {msg}" for msg in feedback)
    else:
        feedback_str = "No major issues found."

    return rating, f"Score: {score}/{MAX_SCORE}\nSuggestions:\n{feedback_str}"

# --- MAIN APPLICATION LOGIC ---

# Global State variables to hold the active key and vault data
MASTER_KEY = None
VAULT = {}
SALT = None

def set_master_password_flow() -> bool:
    """Handles first-time password setup and file creation."""
    global MASTER_KEY, SALT
    print("\n🔐 WELCOME! First-time setup required.")
    
    while True:
        master_pwd = getpass("Set your Master Password (Min 12 Chars): ")
        if len(master_pwd) < 12:
            print("Master password must be at least 12 characters long.")
            continue
        
        MASTER_KEY, SALT = generate_key_materials(master_pwd)
        save_key_materials(SALT)
        
        try:
            # Test key validity
            test_token = encrypt_data("test_data", MASTER_KEY)
            if decrypt_data(test_token, MASTER_KEY) == "test_data":
                print("✅ Setup complete. Security files created.")
                return True # SUCCESS
            else:
                 raise Exception("Key validation failed.")
        except Exception:
             print("🚨 Error during key creation test. Please try again.")
             MASTER_KEY = None
             SALT = None

def authenticate_master_password_flow() -> bool:
    """Requires and checks the existing master password for access."""
    global MASTER_KEY, VAULT, SALT

    print("\n🔐 WELCOME BACK! Authentication required.")
    
    for attempt in range(1, 4):
        master_pwd = getpass(f"Enter Master Password (Attempt {attempt}/3): ")
        key_attempt = derive_key(master_pwd, SALT)
        
        try:
            # Attempt to load the vault. This will only succeed if the key is correct.
            VAULT = load_vault(key_attempt)
            MASTER_KEY = key_attempt
            print("✅ Login successful. Access granted.")
            return True # SUCCESS
        except Exception:
            pass
        
        print("❌ Invalid Master Password. Try again.")

    print("🚨 Too many failed attempts. Access denied.")
    return False # FAILURE

def init_manager() -> bool:
    """Determines whether to set up or authenticate."""
    global SALT
    SALT = load_salt()
    
    if SALT is None:
        return set_master_password_flow()
    else:
        return authenticate_master_password_flow()

# --- UTILITY FUNCTIONS ---

def add_password():
    """Prompts user for a new entry and saves it."""
    site = input("Enter website/service name: ").strip().lower()
    username = input("Enter username/email: ").strip()
    
    while True:
        password = getpass("Enter password (will be checked for strength): ")
        rating, feedback = check_strength(password)
        print(f"\nPassword Strength: {rating}\n{feedback}\n")
        
        if rating in ("👍 Strong", "⭐ Excellent"):
            VAULT[site] = {'username': username, 'password': password}
            save_vault(VAULT, MASTER_KEY)
            print(f"✅ Password for {site} added and secured.")
            break
        else:
            choice = input("Password is weak. Save anyway? (y/N): ").lower()
            if choice == 'y':
                VAULT[site] = {'username': username, 'password': password}
                save_vault(VAULT, MASTER_KEY)
                print(f"⚠️ Weak password for {site} saved.")
                break
            else:
                 print("Generation cancelled.")
                 break

def retrieve_password():
    """Prompts for site and displays decrypted password."""
    site = input("Enter website/service to retrieve: ").strip().lower()
    
    if not VAULT:
        print("Vault is empty. Add some passwords first.")
        return

    if site in VAULT:
        print("-" * 30)
        print(f"Site:     {site.upper()}")
        print(f"Username: {VAULT[site]['username']}")
        print(f"Password: {VAULT[site]['password']}")
        print("-" * 30)
    else:
        print(f"❌ Account for '{site}' not found. Available sites: {', '.join(VAULT.keys())}")

def view_all_entries():
    """NEW FUNCTION: Lists all saved website and username pairs."""
    if not VAULT:
        print("\nVault is empty. Add some passwords first.")
        return

    print("\n" + "="*30)
    print("ALL SAVED ENTRIES")
    print("="*30)
    print(f"{'SITE':<20} {'USERNAME':<30}")
    print("-" * 50)
    
    # VAULT is a dictionary of dictionaries, e.g., {'google': {'username': '...', 'password': '...'}}
    for site, data in VAULT.items():
        print(f"{site.upper():<20} {data['username']:<30}")
    print("-" * 50)


def generate_password():
    """Generates a strong, random password."""
    length = 16
    characters = string.ascii_letters + string.digits + string.punctuation
    
    for _ in range(5):
        password_list = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice(string.punctuation)
        ]
        password_list += [secrets.choice(characters) for _ in range(length - 4)]
        
        secrets.SystemRandom().shuffle(password_list)
        generated_password = "".join(password_list)
        
        rating, _ = check_strength(generated_password)
        
        if rating in ("⭐ Excellent"):
            print("-" * 40)
            print(f"✨ Generated Password: {generated_password}")
            print(f"Strength: {rating}")
            print("-" * 40)
            return
            
    print("Could not generate an 'Excellent' password quickly. Please try again.")


def main_menu():
    """The main application loop, only accessible after successful authentication."""
    while True:
        print("\n" + "="*30)
        print("PASSWORD SECURITY SUITE MENU")
        print("="*30)
        
        print("1. Add New Password/Entry")
        print("2. Retrieve Specific Password (View Password)")
        print("3. View All Saved Entries (List Websites & Users) ⭐")
        print("4. Generate Strong Password")
        print("5. Check Custom Password Strength")
        print("6. Exit") # Updated to 6
        
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            add_password()
        elif choice == '2':
            retrieve_password()
        elif choice == '3': # NEW FUNCTIONALITY
            view_all_entries()
        elif choice == '4':
            generate_password()
        elif choice == '5':
            pwd_to_check = getpass("Enter password to check: ")
            rating, feedback = check_strength(pwd_to_check)
            print(f"\nPassword Strength: {rating}\n{feedback}")
        elif choice == '6':
            print("👋 Saving vault and exiting. Goodbye!")
            break
        else:
            print("❗ Invalid choice. Please select a number from 1 to 6.")

if __name__ == "__main__":
    if init_manager():
        main_menu()
    else:
        pass