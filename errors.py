"""
Hierarchical error classes for Post-Quantum JWT Manager
Using nested classes for organization while keeping single file
"""

class JWTBaseError(Exception):
    """Base exception for all JWT-related errors"""
    pass


# Main error categories as classes (not instantiated)
class JWTError:
    """Namespace for JWT error categories"""
    
    class Validation(JWTBaseError):
        """Base class for validation-related errors"""
        pass
    
    class Key(JWTBaseError):
        """Base class for key-related errors"""
        pass
    
    class Algorithm(JWTBaseError):
        """Base class for algorithm-related errors"""
        pass
    
    class Format(JWTBaseError):
        """Base class for format-related errors"""
        pass
    
    class Claims(JWTBaseError):
        """Base class for claims-related errors"""
        pass
    
    class Permission(JWTBaseError):
        """Base class for permission-related errors"""
        pass
    
    class Config(JWTBaseError):
        """Base class for configuration errors"""
        pass


# JWT Validation Errors
class MalformedJWTError(JWTError.Validation):
    """Raised when JWT structure is malformed"""

class InvalidSignatureError(JWTError.Validation):
    """Raised when JWT signature is invalid"""

class DecodingError(JWTError.Validation):
    """Raised when JWT decoding fails"""

class Base64DecodingError(DecodingError):
    """Raised when Base64 decoding fails"""

class JSONDecodingError(DecodingError):
    """Raised when JSON decoding fails"""


# Key-related Errors
class KeyNotFoundError(JWTError.Key):
    """Raised when a key file is not found"""

class KeyGenerationError(JWTError.Key):
    """Raised when key generation fails"""

class KeyLoadingError(JWTError.Key):
    """Raised when key loading fails"""

class KeyFormatError(JWTError.Key):
    """Raised when key format is invalid"""

class KeySerializationError(JWTError.Key):
    """Raised when key serialization fails"""


# Algorithm-related Errors
class AlgorithmNotSupportedError(JWTError.Algorithm):
    """Raised when an algorithm is not supported"""

class AlgorithmMismatchError(JWTError.Algorithm):
    """Raised when there's a mismatch between expected and actual algorithm"""


# Format-related Errors
class InvalidFormatError(JWTError.Format):
    """Raised when an invalid format is specified"""

class PEMFormatError(JWTError.Format):
    """Raised when PEM format is invalid"""

class PUBFormatError(JWTError.Format):
    """Raised when PUB format is invalid"""

class BinaryFormatError(JWTError.Format):
    """Raised when binary format is invalid"""


# Claims-related Errors
class ExpiredTokenError(JWTError.Claims):
    """Raised when JWT has expired"""

class NotYetValidError(JWTError.Claims):
    """Raised when JWT is not yet valid (nbf)"""

class InvalidIssuedAtError(JWTError.Claims):
    """Raised when 'iat' claim is in the future"""

class InvalidClaimError(JWTError.Claims):
    """Raised when a claim has an invalid value or type"""


# Permission Errors
class UnauthorizedOperationError(JWTError.Permission):
    """Raised when an operation is not permitted for the current mode"""

class PublisherRequiredError(UnauthorizedOperationError):
    """Raised when publisher mode is required but not set"""


# Configuration Errors
class ConfigurationError(JWTError.Config):
    """Raised when there's a configuration error"""

class InvalidModeError(ConfigurationError):
    """Raised when an invalid mode is specified"""