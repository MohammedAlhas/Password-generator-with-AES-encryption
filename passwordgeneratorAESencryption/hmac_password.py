import hmac
import hashlib
import base64
import os

def hmac_password(password, key=None):
    if key is None:
        key = os.urandom(16)  # Generate a random key
    hashed_password = hmac.new(key, password.encode(), hashlib.sha256).digest()
    return base64.b64encode(key + hashed_password).decode('utf-8')

if __name__ == "__main__":
    password = input("Enter the password to hash: ")
    print("HMAC Hashed Password:", hmac_password(password))
