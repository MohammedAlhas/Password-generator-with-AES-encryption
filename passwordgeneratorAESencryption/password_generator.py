import random
import string
import hashlib
import hmac
import os
import base64
import bcrypt
from cryptography.fernet import Fernet

# Function to generate a key for AES encryption
def generate_key():
    return Fernet.generate_key()

# Function to encrypt a message
def encrypt_message(key, message):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

# Function to decrypt a message
def decrypt_message(key, encrypted_message):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

# Random Password Generator
def random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# SHA-256 Password Hashing
def sha256_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# HMAC Password Hashing
def hmac_password(password, key=None):
    if key is None:
        key = os.urandom(16)  # Generate a random key
    hashed_password = hmac.new(key, password.encode(), hashlib.sha256).digest()
    return base64.b64encode(key + hashed_password).decode('utf-8')

# bcrypt Password Hashing
def bcrypt_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Main function to run all algorithms
def main():
    print("Password Generator Tool")
    base_password = input("Enter the base password: ")
    random_length = int(input("Enter the length for the random password: "))
    
    # Generate AES encryption key
    aes_key = generate_key()
    print(f"AES Encryption Key (keep this secret): {aes_key.decode()}")

    # Generate Random Password
    random_pw = random_password(random_length)
    print("\nGenerated Passwords:")
    print(f"Random Password: {random_pw}")

    # Generate SHA-256 Hashed Password
    sha256_pw = sha256_password(base_password)
    print(f"SHA-256 Hashed Password: {sha256_pw}")

    # Generate HMAC Hashed Password
    hmac_pw = hmac_password(base_password)
    print(f"HMAC Hashed Password: {hmac_pw}")

    # Generate bcrypt Hashed Password
    bcrypt_pw = bcrypt_password(base_password)
    print(f"bcrypt Hashed Password: {bcrypt_pw}")

    # Encrypt the generated passwords
    encrypted_random_pw = encrypt_message(aes_key, random_pw)
    encrypted_sha256_pw = encrypt_message(aes_key, sha256_pw)
    encrypted_hmac_pw = encrypt_message(aes_key, hmac_pw)
    encrypted_bcrypt_pw = encrypt_message(aes_key, bcrypt_pw)

    print("\nEncrypted Passwords:")
    print(f"Encrypted Random Password: {encrypted_random_pw}")
    print(f"Encrypted SHA-256 Hashed Password: {encrypted_sha256_pw}")
    print(f"Encrypted HMAC Hashed Password: {encrypted_hmac_pw}")
    print(f"Encrypted bcrypt Hashed Password: {encrypted_bcrypt_pw}")

if __name__ == "__main__":
    main()
