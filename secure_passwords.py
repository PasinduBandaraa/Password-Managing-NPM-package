# secure_passwords.py

import secrets
from argon2 import PasswordHasher

class SecurePasswords:
    def __init__(self):
        self.ph = PasswordHasher()

    def hash_password(self, password):
        # Generate a random salt
        salt = secrets.token_hex(16)

        # Hash the password with Argon2 and the generated salt
        hashed_password = self.ph.hash(password + salt)

        return hashed_password, salt

    def verify_password(self, hashed_password, salt, input_password):
        # Verify the input password against the stored hash and salt
        return self.ph.verify(hashed_password, input_password + salt)

# Example usage
if __name__ == "__main__":
    secure_password_manager = SecurePasswords()

    # Hash a password
    password_to_store = "user_password"
    hashed_password, salt = secure_password_manager.hash_password(password_to_store)

    # Save hashed_password and salt in your database

    # Verify a password
    user_input_password = "user_password"
    is_password_valid = secure_password_manager.verify_password(hashed_password, salt, user_input_password)

    if is_password_valid:
        print("Password is valid!")
    else:
        print("Invalid password!")
