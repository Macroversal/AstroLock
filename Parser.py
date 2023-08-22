# parser.py
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Python Encryption/Decryption Tool")
    subparsers = parser.add_subparsers(dest='action', help='Choose an action:')

    symmetric_parser = subparsers.add_parser('symmetric', help='Use symmetric encryption')
    symmetric_parser.add_argument('message', help='Message to encrypt')

    asymmetric_parser = subparsers.add_parser('asymmetric', help='Use asymmetric encryption')
    asymmetric_parser.add_argument('message', help='Message to encrypt')

    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a message')
    decrypt_parser.add_argument('--decryption_key', help='Decryption key (hex format)', required=True)
    decrypt_parser.add_argument('--encrypted_message', help='Encrypted message (hex format)', required=True)

    return parser.parse_args()