# Password Generator Tool

This project provides a password generation and hashing tool using various algorithms, including bcrypt, HMAC, SHA-256, and random password generation. Additionally, it incorporates AES encryption to secure generated passwords.
## Overview of AES Encryption

**AES (Advanced Encryption Standard)** is a symmetric encryption algorithm widely used to secure data. It encrypts data in fixed-size blocks (128 bits) using a secret key of specified length (128, 192, or 256 bits). AES is considered secure and efficient, making it suitable for encrypting sensitive information, such as passwords.# Password-generator-with-AES-encryption

**This project utilizes various cryptographic algorithms and libraries for secure password handling.**

## Scripts Overview

1. **`bcrypt_password.py`**
   - This script hashes a given password using the bcrypt hashing algorithm.
   - **Function:**
     ```python
     def bcrypt_password(password):
         salt = bcrypt.gensalt()
         return bcrypt.hashpw(password.encode(), salt).decode()
     ```
   - It prompts the user for a password and prints the hashed result.

2. **`hmac_password.py`**
   - This script generates an HMAC (Hash-based Message Authentication Code) for a given password using SHA-256.
   - **Function:**
     ```python
     def hmac_password(password, key=None):
         if key is None:
             key = os.urandom(16)  # Generate a random key
         hashed_password = hmac.new(key, password.encode(), hashlib.sha256).digest()
         return base64.b64encode(key + hashed_password).decode('utf-8')
     ```
   - It prompts for a password and prints the HMAC hashed result.

3. **`random_password.py`**
   - This script generates a random password of a specified length.
   - **Function:**
     ```python
     def random_password(length=12):
         characters = string.ascii_letters + string.digits + string.punctuation
         return ''.join(random.choice(characters) for i in range(length))
     ```
   - It prompts for the length of the password and prints a randomly generated password.

4. **`sha256_password.py`**
   - This script hashes a given password using the SHA-256 algorithm.
   - **Function:**
     ```python
     def sha256_password(password):
         return hashlib.sha256(password.encode()).hexdigest()
     ```
   - It prompts for a password and prints the SHA-256 hashed result.

5. **`password_generator.py`**
   - This is the main script that combines all functionalities and adds AES encryption for the generated passwords.
   - **Functions:**
     - Generates a random password.
     - Hashes the base password using SHA-256, HMAC, and bcrypt.
     - Encrypts the generated passwords using AES encryption.
   - **Key Functions:**
     ```python
     def generate_key():
         return Fernet.generate_key()

     def encrypt_message(key, message):
         fernet = Fernet(key)
         return fernet.encrypt(message.encode()).decode()

     def decrypt_message(key, encrypted_message):
         fernet = Fernet(key)
         return fernet.decrypt(encrypted_message.encode()).decode()
     ```
   - It prompts for a base password and the length for the random password, then displays both plain and encrypted versions of the generated passwords.

## Setup Guide

To run this project, follow these steps:

### Prerequisites

Ensure you have Python installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

# Commands for Password Generator Tool

## Clone the repository
git clone https://github.com/MohammedAlhas/automated-pt-framework.git
cd automated-pt-framework

## install Python and pip
sudo apt update
sudo apt install python3 python3-pip

## create a Virtual Environment (recommended to use a virtual environment to manage dependencies
python3 -m venv venv
source venv/bin/activate

## Install the required packages
pip install bcrypt cryptography

## Run any individual script
python <script_name>.py

## Run the main password generator tool
python password_generator.py
