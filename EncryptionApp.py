# encryption.py
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from pip._internal.utils import hashes
from Constants import ADMIN_USERNAME, ADMIN_PASSWORD, ERROR_MESSAGES
from Exceptions import AuthenticationError, InvalidKeyFormatError, InvalidMessageFormatError, DecryptionFailedError, UnknownError

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
        """Encrypt a given message using the provided public key.

        Args:
            message (str): The message to be encrypted.
            public_key: The recipient's public key.

        Returns:
            bytes: Encrypted message.
        """
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
        """Decrypt the given encrypted message using the provided private key.

        Args:
            encrypted_message (bytes): The encrypted message.
            private_key: The recipient's private key.

        Returns:
            str: Decrypted message.
        """
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
