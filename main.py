import logging
from cryptography.fernet import Fernet
import argparse
import getpass
import cryptography.fernet
import sys

# Constants
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

class EncryptionApp:
    def __init__(self):
        self.key = None

    def generate_key(self):
        return Fernet.generate_key()

    def encrypt_message(self, message, key):
        cipher_suite = Fernet(key)
        encrypted_message = cipher_suite.encrypt(message.encode())
        return encrypted_message

    def run(self):
        logging.basicConfig(filename='encryption_app.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.key = self.generate_key()
        logging.info("Encryption Key generated")

        print("Encryption Key:", self.key.decode())
        logging.info("Encryption Key displayed")

        message = input("Enter the message to encrypt: ")

        try:
            encrypted_message = self.encrypt_message(message, self.key)
            print("Message Encrypted Successfully.")
            print("Encrypted Message:", encrypted_message.decode())
            logging.info("Message Encrypted Successfully")
        except Exception as e:
            print("An error occurred during encryption:", e)
            logging.error("An error occurred during encryption: %s", e)

class DecryptionApp:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def authenticate(self):
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")
        return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

    def validate_hex(self, input_str):
        return all(c in '0123456789abcdefABCDEF' for c in input_str)

    def decrypt_message(self, encrypted_message, decryption_key):
        cipher_suite = Fernet(decryption_key)
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        return decrypted_message.decode()

    def run(self, decryption_key, encrypted_message_input):
        if not self.authenticate():
            print("Authentication failed.")
            return

        try:
            decryption_key = decryption_key.strip()
            if not self.validate_hex(decryption_key):
                print("Invalid decryption key format. Please enter the key in hex format.")
                return

            self.logger.info("Decryption Key entered securely")

            encrypted_message_input = encrypted_message_input.strip()
            if not self.validate_hex(encrypted_message_input):
                print("Invalid encrypted message format. Please enter the message in hex format.")
                return

            encrypted_message = bytes.fromhex(encrypted_message_input)
            decrypted_message = self.decrypt_message(encrypted_message, decryption_key.encode())
            print("Decrypted Message:", decrypted_message)
            self.logger.info("Message Decrypted Successfully")
        except KeyboardInterrupt:
            print("\nDecryption process interrupted.")
            self.logger.info("Decryption process interrupted.")
        except cryptography.fernet.InvalidToken:
            print("Decryption failed. The provided key might be incorrect or the message has been tampered with.")
            print("Make sure the decryption key and encrypted message are correct.")
        except Exception as e:
            print("An error occurred during decryption:", e)
            print("Please check if the decryption key and encrypted message are correct.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Encryption/Decryption Tool")
    subparsers = parser.add_subparsers(dest='action', help='Choose an action:')

    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a message')
    encrypt_parser.add_argument('message', help='Message to encrypt')

    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a message')
    decrypt_parser.add_argument('--decryption_key', help='Decryption key (hex format)', required=True)
    decrypt_parser.add_argument('--encrypted_message', help='Encrypted message (hex format)', required=True)

    args = parser.parse_args()

    if args.action == 'encrypt':
        encryption_app = EncryptionApp()
        encryption_app.run(args.message)
    elif args.action == 'decrypt':
        decryption_app = DecryptionApp()
        decryption_app.run(args.decryption_key, args.encrypted_message)
    else:
        parser.print_help()
