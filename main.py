import logging
from cryptography.fernet import Fernet
import argparse
import getpass
import cryptography.fernet
import sys

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
    def decrypt_message(self, encrypted_message, decryption_key):
        cipher_suite = Fernet(decryption_key)
        decrypted_message = cipher_suite.decrypt(encrypted_message)
        return decrypted_message.decode()

    def authenticate(self):
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")
        # Here you can perform authentication based on username and password
        # For demonstration purposes, let's assume username is "admin" and password is "password"
        if username == "admin" and password == "password":
            return True
        else:
            return False

    def run(self, decryption_key, encrypted_message_input):
        if not self.authenticate():
            print("Authentication failed.")
            return

    def validate_hex_key(self, key_input):
        return all(c in '0123456789abcdefABCDEF' for c in key_input)

    def validate_hex_message(self, message_input):
        return all(c in '0123456789abcdefABCDEF' for c in message_input)

    def run(self):
        logging.basicConfig(filename='decryption_app.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        try:
            decryption_key = getpass.getpass("Enter the decryption key (hex format): ").strip()
            if not self.validate_hex_key(decryption_key):
                print("Invalid decryption key format. Please enter the key in hex format.")
                logging.error("Invalid decryption key format.")
                return
            logging.info("Decryption Key entered securely")

            encrypted_message_input = input("Enter the encrypted message (hex format): ").strip()
            if not self.validate_hex_message(encrypted_message_input):
                print("Invalid encrypted message format. Please enter the message in hex format.")
                logging.error("Invalid encrypted message format.")
                return

            encrypted_message = bytes.fromhex(encrypted_message_input)
            decrypted_message = self.decrypt_message(encrypted_message, decryption_key.encode())
            print("Decrypted Message:", decrypted_message)
            logging.info("Message Decrypted Successfully")
        except KeyboardInterrupt:
            print("\nDecryption process interrupted.")
            logging.info("Decryption process interrupted.")
        except cryptography.fernet.InvalidToken:
            print("Decryption failed. The provided key might be incorrect or the message has been tampered with.")
            logging.error("Decryption failed")
        except Exception as e:
            print("An error occurred during decryption:", e)
            logging.error("An error occurred during decryption: %s", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Encryption/Decryption Tool")
    parser.add_argument("--encrypt", help="Encrypt a message")
    parser.add_argument("--decrypt", help="Decrypt a message (requires decryption key and encrypted message arguments)")
    parser.add_argument("--decryption_key", help="Decryption key (hex format)", required="--decrypt" in sys.argv)
    parser.add_argument("--encrypted_message", help="Encrypted message (hex format)", required="--decrypt" in sys.argv)

    args = parser.parse_args()

    if args.encrypt:
        encryption_app = EncryptionApp()
        encryption_app.run(args.encrypt)
    elif args.decrypt:
        decryption_app = DecryptionApp()
        decryption_app.run(args.decryption_key, args.encrypted_message)
    else:
        print("No valid action provided. Use --encrypt or --decrypt.")
