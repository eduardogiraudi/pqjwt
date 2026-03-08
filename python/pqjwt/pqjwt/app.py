import json
import base64
import os
import time
from typing import Dict, Any, Optional, Tuple, Union

# dilithium
from pqcrypto.sign.ml_dsa_44 import generate_keypair as generate_keypair_44, sign as sign_44, verify as verify_44
from pqcrypto.sign.ml_dsa_65 import generate_keypair as generate_keypair_65, sign as sign_65, verify as verify_65
from pqcrypto.sign.ml_dsa_87 import generate_keypair as generate_keypair_87, sign as sign_87, verify as verify_87
# falcon
from pqcrypto.sign.falcon_padded_512 import generate_keypair as generate_keypair_falcon512, sign as sign_falcon512, verify as verify_falcon512
from pqcrypto.sign.falcon_padded_1024 import generate_keypair as generate_keypair_falcon1024, sign as sign_falcon1024, verify as verify_falcon1024
# sphincs
from pqcrypto.sign.sphincs_sha2_128f_simple import generate_keypair as generate_keypair_sphincs128f, sign as sign_sphincs128f, verify as verify_sphincs128f
from pqcrypto.sign.sphincs_sha2_128s_simple import generate_keypair as generate_keypair_sphincs128s, sign as sign_sphincs128s, verify as verify_sphincs128s
from pqcrypto.sign.sphincs_sha2_192f_simple import generate_keypair as generate_keypair_sphincs192f, sign as sign_sphincs192f, verify as verify_sphincs192f
from pqcrypto.sign.sphincs_sha2_192s_simple import generate_keypair as generate_keypair_sphincs192s, sign as sign_sphincs192s, verify as verify_sphincs192s
from pqcrypto.sign.sphincs_sha2_256f_simple import generate_keypair as generate_keypair_sphincs256f, sign as sign_sphincs256f, verify as verify_sphincs256f
from pqcrypto.sign.sphincs_sha2_256s_simple import generate_keypair as generate_keypair_sphincs256s, sign as sign_sphincs256s, verify as verify_sphincs256s
from pqcrypto.sign.sphincs_shake_128f_simple import generate_keypair as generate_keypair_sphincs_shake128f, sign as sign_sphincs_shake128f, verify as verify_sphincs_shake128f
from pqcrypto.sign.sphincs_shake_128s_simple import generate_keypair as generate_keypair_sphincs_shake128s, sign as sign_sphincs_shake128s, verify as verify_sphincs_shake128s
from pqcrypto.sign.sphincs_shake_192f_simple import generate_keypair as generate_keypair_sphincs_shake192f, sign as sign_sphincs_shake192f, verify as verify_sphincs_shake192f
from pqcrypto.sign.sphincs_shake_192s_simple import generate_keypair as generate_keypair_sphincs_shake192s, sign as sign_sphincs_shake192s, verify as verify_sphincs_shake192s
from pqcrypto.sign.sphincs_shake_256f_simple import generate_keypair as generate_keypair_sphincs_shake256f, sign as sign_sphincs_shake256f, verify as verify_sphincs_shake256f
from pqcrypto.sign.sphincs_shake_256s_simple import generate_keypair as generate_keypair_sphincs_shake256s, sign as sign_sphincs_shake256s, verify as verify_sphincs_shake256s
from . import errors
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder
from pyasn1.codec.der import decoder
ALGORITHM_OIDS = {
    'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
    'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
    'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
    'FN-DSA-512': '1.3.9999.3.6',
    'FN-DSA-1024': '1.3.9999.3.7',
    'SLH-DSA-SHA2-128s': '2.16.840.1.101.3.4.3.20',
    'SLH-DSA-SHA2-128f': '2.16.840.1.101.3.4.3.21',
    'SLH-DSA-SHA2-192s': '2.16.840.1.101.3.4.3.22',
    'SLH-DSA-SHA2-192f': '2.16.840.1.101.3.4.3.23',
    'SLH-DSA-SHA2-256s': '2.16.840.1.101.3.4.3.24',
    'SLH-DSA-SHA2-256f': '2.16.840.1.101.3.4.3.25',
    'SLH-DSA-SHAKE-128s': '2.16.840.1.101.3.4.3.26',
    'SLH-DSA-SHAKE-128f': '2.16.840.1.101.3.4.3.27',
    'SLH-DSA-SHAKE-192s': '2.16.840.1.101.3.4.3.28',
    'SLH-DSA-SHAKE-192f': '2.16.840.1.101.3.4.3.29',
    'SLH-DSA-SHAKE-256s': '2.16.840.1.101.3.4.3.30',
    'SLH-DSA-SHAKE-256f': '2.16.840.1.101.3.4.3.31'
}

class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id', univ.ObjectIdentifier())
    )

class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('subjectPublicKey', univ.BitString())
    )

class OneAsymmetricKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('privateKey', univ.OctetString())
    )

class JWTKeyManager:
    """
    Security Notes:
        - ML-DSA: NIST Standardized (FIPS 204), no known practical attacks
        - Falcon Padded: Mitigates timing attacks present in basic Falcon variants
        - SPHINCS+: Conservative hash-based security, very large signatures but no lattice attacks
    """
    ALGORITHMS = {
        "ML-DSA-44": {
            "generate": generate_keypair_44,
            "sign": sign_44,
            "verify": verify_44,
            "jwt_header": "ML-DSA-44"
        },
        "ML-DSA-65": {
            "generate": generate_keypair_65,
            "sign": sign_65,
            "verify": verify_65,
            "jwt_header": "ML-DSA-65"
        },
        "ML-DSA-87": {
            "generate": generate_keypair_87,
            "sign": sign_87,
            "verify": verify_87,
            "jwt_header": "ML-DSA-87"
        },
        "FN-DSA-512": {
            "generate": generate_keypair_falcon512,
            "sign": sign_falcon512,
            "verify": verify_falcon512,
            "jwt_header": "FN-DSA-512",
        },
        "FN-DSA-1024": {
            "generate": generate_keypair_falcon1024,
            "sign": sign_falcon1024,
            "verify": verify_falcon1024,
            "jwt_header": "FN-DSA-1024",
        },
        "SLH-DSA-SHA2-128f": {
            "generate": generate_keypair_sphincs128f,
            "sign": sign_sphincs128f,
            "verify": verify_sphincs128f,
            "jwt_header": "SLH-DSA-SHA2-128f",
        },
        "SLH-DSA-SHA2-128s": {
            "generate": generate_keypair_sphincs128s,
            "sign": sign_sphincs128s,
            "verify": verify_sphincs128s,
            "jwt_header": "SLH-DSA-SHA2-128s",
        },
        "SLH-DSA-SHA2-192f": {
            "generate": generate_keypair_sphincs192f,
            "sign": sign_sphincs192f,
            "verify": verify_sphincs192f,
            "jwt_header": "SLH-DSA-SHA2-192f",
        },
        "SLH-DSA-SHA2-192s": {
            "generate": generate_keypair_sphincs192s,
            "sign": sign_sphincs192s,
            "verify": verify_sphincs192s,
            "jwt_header": "SLH-DSA-SHA2-192s",
        },
        "SLH-DSA-SHA2-256f": {
            "generate": generate_keypair_sphincs256f,
            "sign": sign_sphincs256f,
            "verify": verify_sphincs256f,
            "jwt_header": "SLH-DSA-SHA2-256f",
        },
        "SLH-DSA-SHA2-256s": {
            "generate": generate_keypair_sphincs256s,
            "sign": sign_sphincs256s,
            "verify": verify_sphincs256s,
            "jwt_header": "SLH-DSA-SHA2-256s",
        },
        "SLH-DSA-SHAKE-128f": {
            "generate": generate_keypair_sphincs_shake128f,
            "sign": sign_sphincs_shake128f,
            "verify": verify_sphincs_shake128f,
            "jwt_header": "SLH-DSA-SHAKE-128f",
        },
        "SLH-DSA-SHAKE-128s": {
            "generate": generate_keypair_sphincs_shake128s,
            "sign": sign_sphincs_shake128s,
            "verify": verify_sphincs_shake128s,
            "jwt_header": "SLH-DSA-SHAKE-128s",
        },
        "SLH-DSA-SHAKE-192f": {
            "generate": generate_keypair_sphincs_shake192f,
            "sign": sign_sphincs_shake192f,
            "verify": verify_sphincs_shake192f,
            "jwt_header": "SLH-DSA-SHAKE-192f",
        },
        "SLH-DSA-SHAKE-192s": {
            "generate": generate_keypair_sphincs_shake192s,
            "sign": sign_sphincs_shake192s,
            "verify": verify_sphincs_shake192s,
            "jwt_header": "SLH-DSA-SHAKE-192s",
        },
        "SLH-DSA-SHAKE-256f": {
            "generate": generate_keypair_sphincs_shake256f,
            "sign": sign_sphincs_shake256f,
            "verify": verify_sphincs_shake256f,
            "jwt_header": "SLH-DSA-SHAKE-256f",
        },
        "SLH-DSA-SHAKE-256s": {
            "generate": generate_keypair_sphincs_shake256s,
            "sign": sign_sphincs_shake256s,
            "verify": verify_sphincs_shake256s,
            "jwt_header": "SLH-DSA-SHAKE-256s",
        }
    } 

    SUPPORTED_FORMATS = ["pem", "pub", "bin"] 
    
    @classmethod
    def get_supported_algorithms(cls):
        return list(cls.ALGORITHMS.keys())
    
    @classmethod
    def get_jwt_header_name(cls, algorithm: str) -> str:
        if algorithm not in cls.ALGORITHMS:
            raise errors.AlgorithmNotSupportedError(algorithm, list(cls.ALGORITHMS.keys()))
        return cls.ALGORITHMS[algorithm]["jwt_header"]
    
    @classmethod
    def get_algorithm_from_jwt_header(cls, jwt_header: str) -> str:
        for alg, params in cls.ALGORITHMS.items():
            if params["jwt_header"] == jwt_header:
                return alg
        raise errors.AlgorithmNotSupportedError(jwt_header, list(cls.ALGORITHMS.keys()))
    
    @staticmethod
    def save_key(key: bytes, file_path: str, format_type: str = "pem", key_type: str = "public", algorithm: str = "ML-DSA-44"):
        if algorithm not in JWTKeyManager.ALGORITHMS:
            raise errors.AlgorithmNotSupportedError(algorithm, list(JWTKeyManager.ALGORITHMS.keys()))
            
        if format_type == "pem":
            pem_content = JWTKeyManager.bytes_to_pem(key, key_type.upper(), algorithm)
            with open(file_path, "w") as f:
                f.write(pem_content)
        elif format_type == "pub":
            if key_type != "public":
                raise errors.CryptoKeyError("PUB format is for public keys only", key_type=key_type)
            key_hex = key.hex()
            with open(file_path, "w") as f:
                f.write(f"{algorithm} PUBLIC KEY\n{key_hex}")
        elif format_type == "bin":
            with open(file_path, "wb") as f:
                f.write(key)
        else:
            raise errors.KeyFormatError(f"Unsupported format: {format_type}", format_type)
    
    @staticmethod
    def load_key(file_path: str, format_type: str = "auto", key_type: str = "auto", algorithm: str = "auto") -> Tuple[bytes, str]:
        if format_type == "auto":
            format_type = JWTKeyManager._detect_format(file_path)
        detected_algorithm = None
        
        if format_type == "pem":
            with open(file_path, "r") as f:
                content = f.read()
            lines = content.strip().split('\n')
            
            # Estrazione base64 classica
            base64_data = ''.join([line for line in lines if not line.startswith('-----')])
            der_data = base64.b64decode(base64_data)
            
            # DETERMINA SE DECODIFICARE ASN.1
            # Se hai salvato con OID, devi decodificare la struttura
            try:
                if "PRIVATE" in lines[0]:
                    key_type = "private"
                    # Decodifica PKCS#8
                    structure, _ = decoder.decode(der_data, asn1Spec=OneAsymmetricKey())
                    key_data = bytes(structure['privateKey'])
                else:
                    key_type = "public"
                    # Decodifica SubjectPublicKeyInfo
                    structure, _ = decoder.decode(der_data, asn1Spec=SubjectPublicKeyInfo())
                    # Converte BitString in bytes
                    key_data = structure['subjectPublicKey'].asOctets()
            except Exception:
                # Fallback se il PEM era un semplice base64 senza ASN.1
                key_data = der_data
        
            # Logica per l'algoritmo (opzionale: potresti estrarlo dall'OID ASN.1)
            if detected_algorithm is None:
                detected_algorithm = algorithm if algorithm != "auto" else "ML-DSA-44"
                
            return key_data, detected_algorithm
        
        elif format_type == "pub":
            with open(file_path, "r") as f:
                content = f.read()
            lines = content.strip().split('\n')
            if len(lines) < 2:
                raise errors.KeyFormatError("Invalid PUB format")
            if detected_algorithm is None:
                detected_algorithm = algorithm if algorithm != "auto" else "ML-DSA-44"
            return bytes.fromhex(lines[1]), detected_algorithm
        
        elif format_type == "bin":
            with open(file_path, "rb") as f:
                key_data = f.read()
            detected_algorithm = algorithm if algorithm != "auto" else "ML-DSA-44"
            return key_data, detected_algorithm
        
        else:
            raise errors.KeyFormatError(f"Unsupported format: {format_type}", format_type)
    
    @staticmethod
    def _detect_format(file_path: str) -> str:
        if file_path.endswith('.pem'):
            return "pem"
        elif file_path.endswith('.pub'):
            return "pub"
        elif file_path.endswith('.bin'):
            return "bin"
        try:
            with open(file_path, "r", encoding='utf-8') as f:
                first_line = f.readline().strip()
                if "BEGIN PRIVATE KEY" in first_line or "BEGIN PUBLIC KEY" in first_line or "BEGIN ML-DSA-" in first_line:
                    return "pem"
                elif "ML-DSA-" in first_line and "PUBLIC KEY" in first_line:
                    return "pub"
        except:
            pass
        return "bin"
    
    @staticmethod
    def bytes_to_pem(key_bytes: bytes, key_type: str = "PUBLIC", algorithm: str = "ML-DSA-44") -> str:
            if algorithm not in JWTKeyManager.ALGORITHMS:
                raise errors.AlgorithmNotSupportedError(algorithm, list(JWTKeyManager.ALGORITHMS.keys()))
            
            oid = ALGORITHM_OIDS.get(algorithm)
            label = "PUBLIC KEY" if key_type.upper() == "PUBLIC" else "PRIVATE KEY"
    
            if not oid:
                # Fallback per algoritmi senza OID: encoding base64 raw
                key_b64 = base64.b64encode(key_bytes).decode('ascii')
                # Formattazione a 64 caratteri per riga
                key_b64_formatted = "\n".join([key_b64[i:i+64] for i in range(0, len(key_b64), 64)])
                return f"-----BEGIN {label}-----\n{key_b64_formatted}\n-----END {label}-----\n"
            
            # Encoding ASN.1 strutturato (PKCS#8 / SPKI)
            if key_type.upper() == "PUBLIC":
                spki = SubjectPublicKeyInfo()
                spki['algorithm']['id'] = oid
                spki['subjectPublicKey'] = univ.BitString.fromOctetString(key_bytes)
                der_data = encoder.encode(spki)
            else:
                pkcs8 = OneAsymmetricKey()
                pkcs8['version'] = 0
                pkcs8['algorithm']['id'] = oid
                pkcs8['privateKey'] = univ.OctetString(key_bytes)
                der_data = encoder.encode(pkcs8)
            
            b64_text = base64.b64encode(der_data).decode('ascii')
            key_b64_formatted = "\n".join([b64_text[i:i+64] for i in range(0, len(b64_text), 64)])
            
            return f"-----BEGIN {label}-----\n{key_b64_formatted}\n-----END {label}-----\n"

class JWTManager:
    def __init__(self, mode: str = "publisher", key_dir: str = "./keys", 
                 key_format: str = "pem", algorithm: str = "ML-DSA-44"):
        self.mode = mode
        self.key_dir = key_dir
        self.key_format = key_format
        self.algorithm = algorithm
        self.public_key = None
        self.secret_key = None
        
        if algorithm not in JWTKeyManager.ALGORITHMS:
            raise errors.AlgorithmNotSupportedError(algorithm, list(JWTKeyManager.ALGORITHMS.keys()))
        if key_format not in JWTKeyManager.SUPPORTED_FORMATS:
            raise errors.KeyFormatError(f"Unsupported key format: {key_format}", key_format)
        
        os.makedirs(key_dir, exist_ok=True)
        self._load_or_generate_keys()
    
    def _get_key_paths(self) -> Tuple[str, Optional[str]]:
        public_ext = self.key_format if self.key_format != "pub" else "pub"
        public_key_path = os.path.join(self.key_dir, f"{self.algorithm.lower()}_public.{public_ext}")
        secret_key_path = None
        
        if self.mode == "publisher":
            if self.key_format == "pub":
                secret_format = "pem" 
                secret_ext = "pem"    
            else:
                secret_format = self.key_format
                secret_ext = self.key_format
            secret_key_path = os.path.join(self.key_dir, f"{self.algorithm.lower()}_private.{secret_ext}")            
        
        return public_key_path, secret_key_path
    
    def _load_or_generate_keys(self):
        public_key_path, secret_key_path = self._get_key_paths()
        
        if self.mode == "publisher":
            load_public_format = self.key_format
            load_private_format = "pem" if self.key_format == "pub" else self.key_format
            
            if os.path.exists(public_key_path) and (secret_key_path and os.path.exists(secret_key_path)):
                self.public_key, loaded_algorithm = JWTKeyManager.load_key(public_key_path, load_public_format, "public")
                self.secret_key, _ = JWTKeyManager.load_key(secret_key_path, load_private_format, "private")
                
                if loaded_algorithm != self.algorithm:
                    print(f"Warning: Loaded algorithm ({loaded_algorithm}) is different from the requested one ({self.algorithm})")
                    self.algorithm = loaded_algorithm
                
                print(f"Keys for {self.algorithm} loaded from {self.key_dir} (format: {self.key_format})")
            else:
                # Generate new keys
                generate_func = JWTKeyManager.ALGORITHMS[self.algorithm]["generate"]
                self.public_key, self.secret_key = generate_func()
                JWTKeyManager.save_key(self.public_key, public_key_path, load_public_format, "public", self.algorithm)
                JWTKeyManager.save_key(self.secret_key, secret_key_path, load_private_format, "private", self.algorithm)
                print(f"Keys for {self.algorithm} generated and saved in {self.key_dir}")
                print(f"  - Public key: {public_key_path} (format: {load_public_format})")
                print(f"  - Private key: {secret_key_path} (format: {load_private_format})")
        
        elif self.mode == "consumer":
            if os.path.exists(public_key_path):
                self.public_key, loaded_algorithm = JWTKeyManager.load_key(public_key_path, self.key_format, "public")
                if loaded_algorithm != self.algorithm:
                    print(f"Warning: Loaded algorithm ({loaded_algorithm}) is different from the requested one ({self.algorithm})")
                    self.algorithm = loaded_algorithm
                print(f"Public key for {self.algorithm} loaded from {public_key_path}")
            else:
                raise FileNotFoundError(
                    f"Public key not found at {public_key_path}. "
                    "A consumer requires a public key to verify JWTs."
                )
    
    def _base64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    def _base64url_decode(self, data: str) -> bytes:
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    
    def encode(self, payload: Dict[str, Any], headers: Optional[Dict[str, Any]] = None) -> str:
        if self.mode != "publisher":
            raise PermissionError("Only publishers can sign a JWT")
        if self.secret_key is None:
            raise errors.CryptoKeyError("Private key not available for signing")
        
        jwt_header_name = JWTKeyManager.get_jwt_header_name(self.algorithm)
        default_headers = {
            "alg": jwt_header_name,
            "typ": "JWT"
        }
        
        # Merge headers
        if headers:
            default_headers.update(headers)
        
        header_encoded = self._base64url_encode(json.dumps(default_headers, separators=(',', ':'), sort_keys=True).encode('utf-8'))
        payload_encoded = self._base64url_encode(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8'))
        message_to_sign = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        
        sign_func = JWTKeyManager.ALGORITHMS[self.algorithm]["sign"]
        signature = sign_func(self.secret_key, message_to_sign)
        signature_encoded = self._base64url_encode(signature)
        
        jwt = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        return jwt
    
    def decode(self, jwt: str, validate_claims: bool = True, clock_skew: int = 5) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Decode and verify the signature
        """
        try:
            parts = jwt.split('.')
            if len(parts) != 3:
                raise errors.JWTValidationError("Malformed JWT", reason="wrong_number_of_parts")
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            try:
                header_json = self._base64url_decode(header_encoded)
                payload_json = self._base64url_decode(payload_encoded)
                headers = json.loads(header_json.decode('utf-8'))
                payload = json.loads(payload_json.decode('utf-8'))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
                raise errors.JWTDecodeError(f"Error decoding Base64/JSON: {str(e)}")
            
            signature = self._base64url_decode(signature_encoded)
            
            if validate_claims:
                now = time.time()
                
                if 'exp' in payload:
                    exp_time = payload['exp']
                    if not isinstance(exp_time, (int, float)):
                        raise errors.JWTValidationError("Claim 'exp' is not a valid timestamp", claim="exp")
                    if now >= exp_time:
                        raise errors.JWTExpiredError(exp_time=exp_time, current_time=now)


                if 'nbf' in payload:
                    nbf_time = payload['nbf']
                    if not isinstance(nbf_time, (int, float)):
                         raise errors.JWTValidationError("Claim 'nbf' is not a valid timestamp", claim="nbf")
                    if now + clock_skew < nbf_time:
                       raise errors.JWTValidationError(
                           f"JWT not yet valid. Current time: {int(now)}, Not before: {nbf_time}", 
                           claim="nbf"
                       )
                
                if 'iat' in payload:
                    iat_time = payload['iat']
                    if not isinstance(iat_time, (int, float)):
                        raise errors.JWTValidationError("Claim 'iat' is not a valid timestamp", claim="iat")
                    if iat_time > now:
                        raise errors.JWTValidationError("Issued at in future", claim="iat")
            
            jwt_alg = headers.get("alg")
            try:
                expected_algorithm = JWTKeyManager.get_algorithm_from_jwt_header(jwt_alg)
            except errors.AlgorithmNotSupportedError as e:
                raise errors.AlgorithmNotSupportedError(jwt_alg, JWTKeyManager.get_supported_algorithms())
            
            if expected_algorithm != self.algorithm:
                print(f"Warning: JWT algorithm ({expected_algorithm}) differs from the manager's ({self.algorithm})")
            
            verify_func = JWTKeyManager.ALGORITHMS[expected_algorithm]["verify"]
            message_to_verify = f"{header_encoded}.{payload_encoded}".encode('utf-8')
            is_valid = verify_func(self.public_key, message_to_verify, signature)
            
            if not is_valid:
                raise errors.JWTSignatureError(algorithm=expected_algorithm)
            
            return headers, payload
            
        except errors.JWTBaseError:
            raise
        except Exception as e:
            raise errors.JWTValidationError(f"Unexpected error during JWT processing: {str(e)}")
    
    def verify(self, jwt: str) -> bool:
        """
        Verify JWT without decoding the payload
        """
        try:
            self.decode(jwt, validate_claims=False)
            return True
        except errors.JWTBaseError:
            return False
    
    def get_public_key(self, output_format: str = "bytes") -> Union[bytes, str]:
        if output_format == "bytes":
            return self.public_key
        elif output_format == "hex":
            return self.public_key.hex()
        elif output_format == "pem":
            return JWTKeyManager.bytes_to_pem(self.public_key, "PUBLIC", self.algorithm)
        else:
            raise errors.KeyFormatError(f"Unsupported output format: {output_format}")
    
    def export_public_key(self, file_path: str, format_type: str = None):
        if format_type is None:
            format_type = self.key_format
        JWTKeyManager.save_key(self.public_key, file_path, format_type, "public", self.algorithm)
    
    @staticmethod
    def get_supported_algorithms():
        return JWTKeyManager.get_supported_algorithms()


def create_publisher(key_dir: str = "./keys", key_format: str = "pem", algorithm: str = "ML-DSA-44") -> JWTManager:
    return JWTManager(mode="publisher", key_dir=key_dir, key_format=key_format, algorithm=algorithm)

def create_consumer(key_dir: str = "./keys", key_format: str = "pem", algorithm: str = "ML-DSA-44") -> JWTManager:
    return JWTManager(mode="consumer", key_dir=key_dir, key_format=key_format, algorithm=algorithm)

