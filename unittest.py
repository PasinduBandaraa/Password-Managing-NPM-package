# test_secure_password_manager.py
import unittest
from secure_passwords import SecurePasswordManager

class TestSecurePasswordManager(unittest.BaseTestSuite):
    def setUp(self):
        # Create an instance of SecurePasswordManager for testing
        self.password_manager = SecurePasswordManager()

    def test_password_hashing(self):
        # Test case for password hashing
        password = "secure_password123"
        hashed_password = self.password_manager.hash_password(password)
        self.assertIsNotNone(hashed_password)

    def test_password_verification_correct(self):
        # Test case for correct password verification
        password = "secure_password123"
        hashed_password = self.password_manager.hash_password(password)
        is_valid = self.password_manager.verify_password(hashed_password, password)
        self.assertTrue(is_valid)

    def test_password_verification_incorrect(self):
        # Test case for incorrect password verification
        password = "secure_password123"
        hashed_password = self.password_manager.hash_password(password)
        incorrect_password = "wrong_password456"
        is_valid = self.password_manager.verify_password(hashed_password, incorrect_password)
        self.assertFalse(is_valid)

    def test_key_stretching(self):
        # Test case for key stretching
        password = "secure_password123"
        salt = self.password_manager.generate_salt()
        stretched_key = self.password_manager.stretch_key(password, salt)
        self.assertIsNotNone(stretched_key)

if __name__ == "__main__":
    unittest.main()
