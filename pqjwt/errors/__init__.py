from .errors import (
    JWTBaseError,
    JWTExpiredError,
    JWTSignatureError,
    JWTValidationError,
    JWTDecodeError,
    CryptoKeyError,
    AlgorithmNotSupportedError,
    KeyFormatError
)

class jwt:
    ExpiredError = JWTExpiredError
    SignatureError = JWTSignatureError
    ValidationError = JWTValidationError
    DecodeError = JWTDecodeError

class crypto:
    KeyError = CryptoKeyError
    AlgorithmNotSupportedError = AlgorithmNotSupportedError
    KeyFormatError = KeyFormatError

__all__ = [
    'JWTBaseError',
    'JWTExpiredError',
    'JWTSignatureError', 
    'JWTValidationError',
    'JWTDecodeError',
    'CryptoKeyError',
    'AlgorithmNotSupportedError',
    'KeyFormatError',
    'jwt',
    'crypto'
]