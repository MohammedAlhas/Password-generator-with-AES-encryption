import random
import string

def random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

if __name__ == "__main__":
    length = int(input("Enter the length of the random password: "))
    print("Random Password:", random_password(length))
