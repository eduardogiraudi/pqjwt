class JWTBaseError(Exception):
    """Base exception for all JWT-related errors"""
    
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        super().__init__(self.message)
    
    def __str__(self):
        return f"{self.error_code}: {self.message}"

# JWT Errors
class JWTExpiredError(JWTBaseError):
    """Raised when JWT has expired"""
    
    def __init__(self, message: str = "JWT token has expired", exp_time: int = None, current_time: int = None):
        self.exp_time = exp_time
        self.current_time = current_time
        details = message
        if exp_time and current_time:
            details += f" (exp: {exp_time}, current: {current_time})"
        super().__init__(details, "JWT_EXPIRED")

class JWTSignatureError(JWTBaseError):
    """Raised when JWT signature verification fails"""
    
    def __init__(self, message: str = "Invalid JWT signature", algorithm: str = None):
        self.algorithm = algorithm
        details = message
        if algorithm:
            details += f" (algorithm: {algorithm})"
        super().__init__(details, "JWT_SIGNATURE_INVALID")

class JWTValidationError(JWTBaseError):
    """Raised when JWT validation fails for various reasons"""
    
    def __init__(self, message: str = "JWT validation failed", claim: str = None, reason: str = None):
        self.claim = claim
        self.reason = reason
        details = message
        if claim:
            details += f" (claim: {claim})"
        if reason:
            details += f" (reason: {reason})"
        super().__init__(details, "JWT_VALIDATION_FAILED")

class JWTDecodeError(JWTBaseError):
    """Raised when JWT cannot be decoded"""
    
    def __init__(self, message: str = "Error decoding JWT", part: str = None):
        self.part = part
        details = message
        if part:
            details += f" (part: {part})"
        super().__init__(details, "JWT_DECODE_ERROR")

# Crypto Errors
class CryptoKeyError(JWTBaseError):
    """Raised for key-related errors"""
    
    def __init__(self, message: str = "Key management error", key_type: str = None, operation: str = None):
        self.key_type = key_type
        self.operation = operation
        details = message
        if key_type:
            details += f" (key_type: {key_type})"
        if operation:
            details += f" (operation: {operation})"
        super().__init__(details, "CRYPTO_KEY_ERROR")

class AlgorithmNotSupportedError(JWTBaseError):
    """Raised when an algorithm is not supported"""
    
    def __init__(self, algorithm: str, supported_algorithms: list = None):
        self.algorithm = algorithm
        self.supported_algorithms = supported_algorithms
        message = f"Algorithm not supported: {algorithm}"
        if supported_algorithms:
            message += f". Supported: {', '.join(supported_algorithms)}"
        super().__init__(message, "ALGORITHM_NOT_SUPPORTED")

class KeyFormatError(JWTBaseError):
    """Raised for key format errors"""
    
    def __init__(self, message: str = "Key format error", format_type: str = None):
        self.format_type = format_type
        details = message
        if format_type:
            details += f" (format: {format_type})"
        super().__init__(details, "KEY_FORMAT_ERROR")