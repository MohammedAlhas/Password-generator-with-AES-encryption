import bcrypt

def bcrypt_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

if __name__ == "__main__":
    password = input("Enter the password to hash: ")
    print("bcrypt Hashed Password:", bcrypt_password(password))

