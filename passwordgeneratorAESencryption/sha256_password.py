import hashlib

def sha256_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    password = input("Enter the password to hash: ")
    print("SHA-256 Hashed Password:", sha256_password(password))
