from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import os
import base64

# Function to generate a Fernet key from a password
def generate_key_from_password(password):
    salt = b'some_fixed_salt'  # In production, use a secure, unique salt per file
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt files in a directory
def encrypt_files(directory, password):
    key = generate_key_from_password(password)
    fernet = Fernet(key)
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb") as file:
                file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)
            with open(filepath, "wb") as file:
                file.write(encrypted_data)
            print(f"{filename} has been encrypted.")
    print("Encryption successful. You can close the program.")

# Function to decrypt files in a directory with retry attempts
def decrypt_files(directory, password):
    key = generate_key_from_password(password)
    fernet = Fernet(key)
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb") as file:
                encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                with open(filepath, "wb") as file:
                    file.write(decrypted_data)
                print(f"{filename} has been decrypted.")
            except InvalidToken:
                return False  # Incorrect password
    return True  # Decryption successful

# Main function to handle user input with retry attempts for decryption
def main():
    choice = input("Do you want to encrypt or decrypt files? (type 'encrypt' or 'decrypt'): ").strip().lower()
    if choice not in ["encrypt", "decrypt"]:
        print("Invalid choice. Please type 'encrypt' or 'decrypt'.")
        return

    directory = input("Enter the full path of the directory: ").strip()
    if not os.path.isdir(directory):
        print("The specified directory does not exist.")
        return

    password = input("Enter your encryption/decryption key: ").strip()

    if choice == "encrypt":
        encrypt_files(directory, password)
    elif choice == "decrypt":
        attempts = 0
        while attempts < 3:
            success = decrypt_files(directory, password)
            if success:
                print("Decryption successful. You can close the program.")
                break
            else:
                attempts += 1
                if attempts < 3:
                    print("Incorrect password or key. Please try again.")
                    password = input("Enter your decryption key: ").strip()
                else:
                    print("Too many unsuccessful attempts. Program will now close.")
                    break

if __name__ == "__main__":
    main()
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import os
import base64

# Function to generate a Fernet key from a password
def generate_key_from_password(password):
    salt = b'some_fixed_salt'  # In production, use a secure, unique salt per file
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt files in a directory
def encrypt_files(directory, password):
    key = generate_key_from_password(password)
    fernet = Fernet(key)
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb") as file:
                file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)
            with open(filepath, "wb") as file:
                file.write(encrypted_data)
            print(f"{filename} has been encrypted.")
    print("Encryption successful. You can close the program.")

# Function to decrypt files in a directory with retry attempts
def decrypt_files(directory, password):
    key = generate_key_from_password(password)
    fernet = Fernet(key)
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb") as file:
                encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
                with open(filepath, "wb") as file:
                    file.write(decrypted_data)
                print(f"{filename} has been decrypted.")
            except InvalidToken:
                return False  # Incorrect password
    return True  # Decryption successful

# Main function to handle user input with retry attempts for decryption
def main():
    choice = input("Do you want to encrypt or decrypt files? (type 'encrypt' or 'decrypt'): ").strip().lower()
    if choice not in ["encrypt", "decrypt"]:
        print("Invalid choice. Please type 'encrypt' or 'decrypt'.")
        return

    directory = input("Enter the full path of the directory: ").strip()
    if not os.path.isdir(directory):
        print("The specified directory does not exist.")
        return

    password = input("Enter your encryption/decryption key: ").strip()

    if choice == "encrypt":
        encrypt_files(directory, password)
    elif choice == "decrypt":
        attempts = 0
        while attempts < 3:
            success = decrypt_files(directory, password)
            if success:
                print("Decryption successful. You can close the program.")
                break
            else:
                attempts += 1
                if attempts < 3:
                    print("Incorrect password or key. Please try again.")
                    password = input("Enter your decryption key: ").strip()
                else:
                    print("Too many unsuccessful attempts. Program will now close.")
                    break

if __name__ == "__main__":
    main()
