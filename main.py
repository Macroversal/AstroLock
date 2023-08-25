# main.py
from Parser import parse_args
from EncryptionApp import EncryptionApp, AsymmetricEncryptionApp
from DecryptionApp import DecryptionApp
from Constants import ERROR_MESSAGES
from Exceptions import AuthenticationError, InvalidKeyFormatError, InvalidMessageFormatError, DecryptionFailedError, UnknownError

def main():
    args = parse_args()
    parser = parse_args()  # Create the parser instance

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
        parser.print_help()  # Use the parser instance to print help

if __name__ == "__main__":
    main()




