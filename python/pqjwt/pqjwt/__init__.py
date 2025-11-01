"""
PQC JWT - Post-Quantum Cryptography JWT Library

A comprehensive Python library for generating, managing, signing, and verifying 
Post-Quantum Cryptography (PQC) JSON Web Tokens (JWTs). Supports ML-DSA (Dilithium), 
Falcon, and SPHINCS+ digital signature algorithms.
"""

from .app import JWTManager, JWTKeyManager, create_publisher, create_consumer
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

__version__ = "0.1.0"
__author__ = "Eduardo Giraudi"
__email__ = "eduardogiraudi000@gmail.com"
__description__ = "Post-Quantum Cryptography JWT Library"

__all__ = [
    'JWTManager',
    'JWTKeyManager', 
    'create_publisher',
    'create_consumer',
    'JWTBaseError',
    'JWTExpiredError',
    'JWTSignatureError',
    'JWTValidationError',
    'JWTDecodeError',
    'CryptoKeyError',
    'AlgorithmNotSupportedError', 
    'KeyFormatError'
]