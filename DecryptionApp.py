# decryption.py
import logging
import getpass
import cryptography
from cryptography.fernet import Fernet
from Constants import ERROR_MESSAGES, ADMIN_USERNAME, ADMIN_PASSWORD  # Import the constants
from Exceptions import AuthenticationError, InvalidKeyFormatError, InvalidMessageFormatError, DecryptionFailedError, UnknownError

class DecryptionApp:
    """Class for handling decryption operations."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def authenticate(self):
        """Authenticate the user based on username and password."""
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")
        return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

    def validate_hex(self, input_str):
        """Validate if the input string is in valid hex format."""
        return all(c in '0123456789abcdefABCDEF' for c in input_str)

    def decrypt_message(self, encrypted_message, decryption_key):
        """Decrypt the given encrypted message using the provided decryption key."""
        cipher_suite = Fernet(decryption_key)
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        return decrypted_message.decode()

    def run(self, decryption_key, encrypted_message_input):
        """Run the decryption application."""
        if not self.authenticate():
            print(ERROR_MESSAGES["authentication_failed"])
            return

        try:
            decryption_key = decryption_key.strip()
            if not self.validate_hex(decryption_key):
                print(ERROR_MESSAGES["invalid_key_format"])
                return

            self.logger.info("Decryption Key entered securely")

            encrypted_message_input = encrypted_message_input.strip()
            if not self.validate_hex(encrypted_message_input):
                print(ERROR_MESSAGES["invalid_message_format"])
                return

            encrypted_message = bytes.fromhex(encrypted_message_input)
            decrypted_message = self.decrypt_message(encrypted_message, decryption_key.encode())
            print("Decrypted Message:", decrypted_message)
            self.logger.info("Message Decrypted Successfully")
        except KeyboardInterrupt:
            print("\nDecryption process interrupted.")
            self.logger.info("Decryption process interrupted.")
        except cryptography.fernet.InvalidToken:
            print(ERROR_MESSAGES["decryption_failed"])
        except Exception as e:
            print(ERROR_MESSAGES["unknown_error"], e)