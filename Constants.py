# constants.py
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

ERROR_MESSAGES = {
    "authentication_failed": "Authentication failed. Please provide correct credentials.",
    "invalid_key_format": "Invalid key format. Please enter the key in hex format.",
    "invalid_message_format": "Invalid message format. Please enter the message in hex format.",
    "decryption_failed": "Decryption failed. The provided key might be incorrect or the message has been tampered with.",
    "unknown_error": "An unknown error occurred. Please check your input and try again.",
}
