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