import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import hashlib


def generate_salt():
    """Generate a secure random salt."""
    return os.urandom(16)


def hash_password(password, salt):
    """Hash a password using bcrypt and a provided salt."""
    return bcrypt.hashpw(password.encode(), salt)


def check_password(password, hashed):
    """Check if the password matches the hashed value."""
    return bcrypt.checkpw(password.encode(), hashed)


def generate_encryption_key(password, salt):
    """Generate an encryption key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_data(data, key):
    """Encrypt data using a Fernet cipher and the provided key."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data)  # Directly encrypt bytes
    return encrypted_data


def decrypt_data(encrypted_data, key):
    """Decrypt data using a Fernet cipher and the provided key."""
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()
    except Exception as e:
        raise ValueError(f"Failure to decrypt data: {e}")


def verify_data_integrity(encrypted_data, expected_hash):
    """Verify the integrity of the encrypted data by comparing its hash with the expected hash."""
    data_hash = hashlib.sha256(encrypted_data).hexdigest()
    if data_hash != expected_hash:
        raise ValueError("Data integrity check failed. The data may be corrupted.")
