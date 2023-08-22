import logging
import argparse
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from pip._internal.utils import hashes

# Configure logging
logging.basicConfig(filename='encryption_app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

# Error messages dictionary
ERROR_MESSAGES = {
    "authentication_failed": "Authentication failed. Please provide correct credentials.",
    "invalid_key_format": "Invalid key format. Please enter the key in hex format.",
    "invalid_message_format": "Invalid message format. Please enter the message in hex format.",
    "decryption_failed": "Decryption failed. The provided key might be incorrect or the message has been tampered with.",
    "unknown_error": "An unknown error occurred. Please check your input and try again.",
}

# Custom Exceptions
class AuthenticationError(Exception):
    pass

class InvalidKeyFormatError(Exception):
    pass

class InvalidMessageFormatError(Exception):
    pass

class DecryptionFailedError(Exception):
    pass

class UnknownError(Exception):
    pass

class AsymmetricEncryptionApp:
    """Class for handling asymmetric encryption operations."""

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        """Generate a new RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_message(self, message, public_key):
        """Encrypt a given message using the provided public key."""
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt_message(self, encrypted_message, private_key):
        """Decrypt the given encrypted message using the provided private key."""
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()

class EncryptionApp:
    """Class for handling encryption operations."""

    def __init__(self):
        self.key = None

    def generate_key(self):
        """Generate a new encryption key."""
        return Fernet.generate_key()

    def encrypt_message(self, message, key):
        """Encrypt a given message using the provided key."""
        cipher_suite = Fernet(key)
        encrypted_message = cipher_suite.encrypt(message.encode())
        return encrypted_message

    def run(self, message):
        """Run the encryption application."""
        logging.basicConfig(filename='encryption_app.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.key = self.generate_key()
        logging.info("Encryption Key generated")

        print("Encryption Key:", self.key.decode())
        logging.info("Encryption Key displayed")

        try:
            encrypted_message = self.encrypt_message(message, self.key)
            print("Message Encrypted Successfully.")
            print("Encrypted Message:", encrypted_message.decode())
            logging.info("Message Encrypted Successfully")
        except Exception as e:
            print("An error occurred during encryption:", e)
            logging.error("An error occurred during encryption: %s", e)


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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Encryption/Decryption Tool")
    subparsers = parser.add_subparsers(dest='action', help='Choose an action:')

    symmetric_parser = subparsers.add_parser('symmetric', help='Use symmetric encryption')
    symmetric_parser.add_argument('message', help='Message to encrypt')

    asymmetric_parser = subparsers.add_parser('asymmetric', help='Use asymmetric encryption')
    asymmetric_parser.add_argument('message', help='Message to encrypt')

    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a message')
    decrypt_parser.add_argument('--decryption_key', help='Decryption key (hex format)', required=True)
    decrypt_parser.add_argument('--encrypted_message', help='Encrypted message (hex format)', required=True)

    args = parser.parse_args()

    if args.action == 'symmetric':
        encryption_app = EncryptionApp()
        encryption_app.run(args.message)
    elif args.action == 'asymmetric':
        asymmetric_encryption_app = AsymmetricEncryptionApp()
        private_key, public_key = asymmetric_encryption_app.generate_key_pair()
        encrypted_message = asymmetric_encryption_app.encrypt_message(args.message, public_key)
        print("Message Encrypted Successfully.")
        print("Encrypted Message:", encrypted_message.hex())
    elif args.action == 'decrypt':
        decryption_app = DecryptionApp()
        try:
            decryption_app.run(args.decryption_key, args.encrypted_message)
        except AuthenticationError:
            print(ERROR_MESSAGES["authentication_failed"])
        except InvalidKeyFormatError:
            print(ERROR_MESSAGES["invalid_key_format"])
        except InvalidMessageFormatError:
            print(ERROR_MESSAGES["invalid_message_format"])
        except DecryptionFailedError:
            print(ERROR_MESSAGES["decryption_failed"])
        except UnknownError as e:
            print(ERROR_MESSAGES["unknown_error"], e)
    else:
        parser.print_help()