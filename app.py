import json
import base64
import os
import time
from typing import Dict, Any, Optional, Tuple, Union

#dilith
from pqcrypto.sign.ml_dsa_44 import generate_keypair as generate_keypair_44, sign as sign_44, verify as verify_44
from pqcrypto.sign.ml_dsa_65 import generate_keypair as generate_keypair_65, sign as sign_65, verify as verify_65
from pqcrypto.sign.ml_dsa_87 import generate_keypair as generate_keypair_87, sign as sign_87, verify as verify_87
#falcon
from pqcrypto.sign.falcon_padded_512 import generate_keypair as generate_keypair_falcon512, sign as sign_falcon512, verify as verify_falcon512
from pqcrypto.sign.falcon_padded_1024 import generate_keypair as generate_keypair_falcon1024, sign as sign_falcon1024, verify as verify_falcon1024
#sphincs
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
            "jwt_header": "Dilithium2"
        },
        "ML-DSA-65": {
            "generate": generate_keypair_65,
            "sign": sign_65,
            "verify": verify_65,
            "jwt_header": "Dilithium3"
        },
        "ML-DSA-87": {
            "generate": generate_keypair_87,
            "sign": sign_87,
            "verify": verify_87,
            "jwt_header": "Dilithium5"
        },
        "Falcon-512": {
            "generate": generate_keypair_falcon512,
            "sign": sign_falcon512,
            "verify": verify_falcon512,
            "jwt_header": "Falcon512",
        },
        "Falcon-1024": {
            "generate": generate_keypair_falcon1024,
            "sign": sign_falcon1024,
            "verify": verify_falcon1024,
            "jwt_header": "Falcon1024",
        },
        "SPHINCS+-SHA2-128f-simple": {
            "generate": generate_keypair_sphincs128f,
            "sign": sign_sphincs128f,
            "verify": verify_sphincs128f,
            "jwt_header": "SphincsSha2128f",
        },
        "SPHINCS+-SHA2-128s-simple": {
            "generate": generate_keypair_sphincs128s,
            "sign": sign_sphincs128s,
            "verify": verify_sphincs128s,
            "jwt_header": "SphincsSha2128s",
        },
        "SPHINCS+-SHA2-192f-simple": {
            "generate": generate_keypair_sphincs192f,
            "sign": sign_sphincs192f,
            "verify": verify_sphincs192f,
            "jwt_header": "SphincsSha2192f",
        },
        "SPHINCS+-SHA2-192s-simple": {
            "generate": generate_keypair_sphincs192s,
            "sign": sign_sphincs192s,
            "verify": verify_sphincs192s,
            "jwt_header": "SphincsSha2192s",
        },
        "SPHINCS+-SHA2-256f-simple": {
            "generate": generate_keypair_sphincs256f,
            "sign": sign_sphincs256f,
            "verify": verify_sphincs256f,
            "jwt_header": "SphincsSha2256f",
        },
        "SPHINCS+-SHA2-256s-simple": {
            "generate": generate_keypair_sphincs256s,
            "sign": sign_sphincs256s,
            "verify": verify_sphincs256s,
            "jwt_header": "SphincsSha2256s",
        },
        "SPHINCS+-SHAKE-128f-simple": {
            "generate": generate_keypair_sphincs_shake128f,
            "sign": sign_sphincs_shake128f,
            "verify": verify_sphincs_shake128f,
            "jwt_header": "SphincsShake128f",
        },
        "SPHINCS+-SHAKE-128s-simple": {
            "generate": generate_keypair_sphincs_shake128s,
            "sign": sign_sphincs_shake128s,
            "verify": verify_sphincs_shake128s,
            "jwt_header": "SphincsShake128s",
        },
        "SPHINCS+-SHAKE-192f-simple": {
            "generate": generate_keypair_sphincs_shake192f,
            "sign": sign_sphincs_shake192f,
            "verify": verify_sphincs_shake192f,
            "jwt_header": "SphincsShake192f",
        },
        "SPHINCS+-SHAKE-192s-simple": {
            "generate": generate_keypair_sphincs_shake192s,
            "sign": sign_sphincs_shake192s,
            "verify": verify_sphincs_shake192s,
            "jwt_header": "SphincsShake192s",
        },
        "SPHINCS+-SHAKE-256f-simple": {
            "generate": generate_keypair_sphincs_shake256f,
            "sign": sign_sphincs_shake256f,
            "verify": verify_sphincs_shake256f,
            "jwt_header": "SphincsShake256f",
        },
        "SPHINCS+-SHAKE-256s-simple": {
            "generate": generate_keypair_sphincs_shake256s,
            "sign": sign_sphincs_shake256s,
            "verify": verify_sphincs_shake256s,
            "jwt_header": "SphincsShake256s",
        }
    } 

    SUPPORTED_FORMATS = ["pem", "pub", "bin"] 
    
    @classmethod
    def get_supported_algorithms(cls):
        return list(cls.ALGORITHMS.keys())
    
    @classmethod
    def get_jwt_header_name(cls, algorithm: str) -> str:
        if algorithm not in cls.ALGORITHMS:
            raise ValueError(f"Algorithm not supported: {algorithm}")
        return cls.ALGORITHMS[algorithm]["jwt_header"]
    @classmethod
    def get_algorithm_from_jwt_header(cls, jwt_header: str) -> str:
        for alg, params in cls.ALGORITHMS.items():
            if params["jwt_header"] == jwt_header:
                return alg
        raise ValueError(f"JWT header not supported: {jwt_header}")
    @staticmethod
    def save_key(key: bytes, file_path: str, format_type: str = "pem", key_type: str = "public", algorithm: str = "ML-DSA-44"):
        if algorithm not in JWTKeyManager.ALGORITHMS:
            raise ValueError(f"Algorithm not supported: {algorithm}")
        if format_type == "pem":
            if key_type == "private":
                pem_header = "-----BEGIN PRIVATE KEY-----"
                pem_footer = "-----END PRIVATE KEY-----"
            else:
                pem_header = "-----BEGIN PUBLIC KEY-----"
                pem_footer = "-----END PUBLIC KEY-----"
            key_b64 = base64.b64encode(key).decode('ascii')
            pem_content = f"{pem_header}\n{key_b64}\n{pem_footer}"
            with open(file_path, "w") as f:
                f.write(pem_content)
        elif format_type == "pub":
            if key_type != "public":
                raise ValueError("PUB format is for public keys only")
            key_hex = key.hex()
            with open(file_path, "w") as f:
                f.write(f"{algorithm} PUBLIC KEY\n{key_hex}")
        elif format_type == "bin":
            with open(file_path, "wb") as f:
                f.write(key)
        else:
            raise ValueError(f"Unknown format type: {format_type}")
    @staticmethod
    def load_key(file_path: str, format_type: str = "auto", key_type: str = "auto", algorithm: str = "auto") -> Tuple[bytes, str]:
        if format_type == "auto":
            format_type = JWTKeyManager._detect_format(file_path)
        detected_algorithm = None
        if format_type == "pem":
            with open(file_path, "r") as f:
                content = f.read()
            lines = content.strip().split('\n')
            if len(lines) < 3:
                if not any(header in lines[0] for header in ["PRIVATE KEY", "PUBLIC KEY", "ML-DSA"]):
                     raise ValueError("Invalid or unrecognized PEM format")
            base64_data = ''.join(lines[1:-1])
            key_data = base64.b64decode(base64_data)
            first_line = lines[0]
            if "PRIVATE" in first_line:
                if key_type == "auto":
                    key_type = "private"
                '''Wait for ASN.1 support to auto-detect the alg in future'''
            else: 
                if key_type == "auto":
                    key_type = "public"
                '''Wait for ASN.1 support to auto-detect the alg in future'''
            if detected_algorithm is None:
                detected_algorithm = algorithm if algorithm != "auto" else "ML-DSA-44" 
            return key_data, detected_algorithm 
        elif format_type == "pub":
            with open(file_path, "r") as f:
                content = f.read()
            lines = content.strip().split('\n')
            if len(lines) < 2:
                raise ValueError("Invalid PUB format")
            first_line = lines[0]
            '''Wait for ASN.1 support to auto-detect the alg in future'''
            if detected_algorithm is None:
                detected_algorithm = algorithm if algorithm != "auto" else "ML-DSA-44"
            return bytes.fromhex(lines[1]), detected_algorithm
        elif format_type == "bin":
            with open(file_path, "rb") as f:
                key_data = f.read()
            detected_algorithm = algorithm if algorithm != "auto" else "ML-DSA-44"
            return key_data, detected_algorithm
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
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
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        if key_type.upper() == "PUBLIC":
            pem_header = "-----BEGIN PUBLIC KEY-----"
            pem_footer = "-----END PUBLIC KEY-----"
        else:
            pem_header = "-----BEGIN PRIVATE KEY-----"
            pem_footer = "-----END PRIVATE KEY-----"
        key_b64 = base64.b64encode(key_bytes).decode('ascii')
        return f"{pem_header}\n{key_b64}\n{pem_footer}"

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
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if key_format not in JWTKeyManager.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported key format: {key_format}")
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
                #gen new keyss
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
            raise ValueError("Private key not available for signing")
        jwt_header_name = JWTKeyManager.get_jwt_header_name(self.algorithm)
        default_headers = {
            "alg": jwt_header_name,
            "typ": "JWT"
        }
        #merge
        if headers:
            default_headers.update(headers)
        header_encoded = self._base64url_encode(json.dumps(default_headers,separators=(',', ':'), sort_keys=True).encode('utf-8'))
        payload_encoded = self._base64url_encode(json.dumps(payload,separators=(',', ':'), sort_keys=True).encode('utf-8'))
        message_to_sign = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        sign_func = JWTKeyManager.ALGORITHMS[self.algorithm]["sign"]
        signature = sign_func(self.secret_key, message_to_sign)
        signature_encoded = self._base64url_encode(signature)
        jwt = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        return jwt
    def decode(self, jwt: str, validate_claims: bool = True, clock_skew: int = 5) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Decode and verify the sign        
        """
        try:
            parts = jwt.split('.')
            if len(parts) != 3:
                raise ValueError("Malformed JWT")
            header_encoded, payload_encoded, signature_encoded = parts
            header_json = self._base64url_decode(header_encoded)
            payload_json = self._base64url_decode(payload_encoded)
            signature = self._base64url_decode(signature_encoded)
            headers = json.loads(header_json.decode('utf-8'))
            payload = json.loads(payload_json.decode('utf-8'))
            if validate_claims:
                now = time.time()
                if 'exp' in payload:
                    exp_time = payload['exp']
                    if not isinstance(exp_time, (int, float)):
                        raise ValueError("Claim 'exp' is not a valid timestamp.")
                    if now >= exp_time:
                        raise ValueError(f"JWT expired")

                # Controllo 'nbf' (Not Before)
                if 'nbf' in payload:
                    nbf_time = payload['nbf']
                    if not isinstance(nbf_time, (int, float)):
                         raise ValueError("Claim 'nbf' non è un timestamp valido.")
                    if now + clock_skew < nbf_time:
                       raise ValueError(f"JWT non ancora valido. Tempo corrente: {int(now)}, Non prima di: {nbf_time}")
                if 'iat' in payload:
                    iat_time = payload['iat']
                    if not isinstance(iat_time, (int, float)):
                        raise ValueError("Claim 'iat' is not a valid timestamp.")
                    if payload['iat'] > now:
                        raise ValueError("Issued at in future")
            jwt_alg = headers.get("alg")
            expected_algorithm = JWTKeyManager.get_algorithm_from_jwt_header(jwt_alg)
            if expected_algorithm != self.algorithm:
                print(f"Warning: JWT algorithm ({expected_algorithm}) differs from the manager's ({self.algorithm})")
            verify_func = JWTKeyManager.ALGORITHMS[expected_algorithm]["verify"]
            message_to_verify = f"{header_encoded}.{payload_encoded}".encode('utf-8')
            is_valid = verify_func(self.public_key, message_to_verify, signature)
            if not is_valid:
                raise ValueError("Invalid JWT signature")
            return headers, payload
        except Exception as e:
            # Per una migliore gestione degli errori, riclassifichiamo l'errore di decodifica
            if "not a valid JSON" in str(e) or "Incorrect padding" in str(e):
                raise ValueError(f"Error decoding Base64/JSON: {str(e)}")
            raise ValueError(f"Error decoding JWT: {str(e)}")
    def verify(self, jwt: str) -> bool:
        """
        Verify jwt without decoding the payload
        """
        try:
            self.decode(jwt)
            return True
        except (ValueError, Exception):
            return False
    def get_public_key(self, output_format: str = "bytes") -> Union[bytes, str]:
        if output_format == "bytes":
            return self.public_key
        elif output_format == "hex":
            return self.public_key.hex()
        elif output_format == "pem":
            return JWTKeyManager.bytes_to_pem(self.public_key, "PUBLIC", self.algorithm)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
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





















































# Esempio di utilizzo
if __name__ == "__main__":
    print("=== ALGORITMI SUPPORTATI ===")
    supported = JWTManager.get_supported_algorithms()
    print(f"Algoritmi disponibili: {supported}")
    
    if not supported:
        print("\n!!! ATTENZIONE: Nessun algoritmo ML-DSA è disponibile. Assicurati che 'pqcrypto' sia installato correttamente. !!!")
        exit()
        
    print("\n=== ESEMPIO MULTI-ALGORITMO (Signature Check) con PEM Standardizzabile ===")
    
    # Test con diversi algoritmi
    for algorithm in supported:
        print(f"\n--- Test algoritmo {algorithm} ---")
        
        # NOTA: Usiamo il formato 'pem' standardizzabile
        key_dir = f"./keys_{algorithm}" 
        key_format_type = "pem"
        
        try:
            # Publisher
            publisher = create_publisher(key_dir, key_format_type, algorithm)
            payload = {"user": "test", "algorithm": algorithm, "iat": int(time.time()), "exp": int(time.time()) + 600}
            jwt = publisher.encode(payload)
            print(f"JWT generato con {algorithm}: {jwt}...")
            
            # Verifica che l'intestazione PEM sia generica
            pub_pem = publisher.get_public_key("pem")
            print(f"Header PEM Chiave Pubblica: {pub_pem.splitlines()[0]}")
            
            # Consumer
            consumer = create_consumer(key_dir, key_format_type, algorithm)
            is_valid = consumer.verify(jwt)
            print(f"Verifica JWT: {is_valid}")
            
        except Exception as e:
            print(f"Errore con algoritmo {algorithm}: {e}")
            
    # --- TEST CON FORMATO BINARIO ---
    print("\n=== TEST CON FORMATO BINARIO ===")
    algorithm = supported[0]
    key_dir_bin = f"./keys_test_bin_{algorithm}"
    
    try:
        publisher_bin = create_publisher(key_dir_bin, "bin", algorithm)
        payload_bin = {"data": "binary_test", "iat": int(time.time()), "exp": int(time.time()) + 600}
        jwt_bin = publisher_bin.encode(payload_bin)
        print(f"JWT (Binario) generato: {jwt_bin[:50]}...")
        
        consumer_bin = create_consumer(key_dir_bin, "bin", algorithm)
        is_valid_bin = consumer_bin.verify(jwt_bin)
        print(f"Verifica JWT (Binario): {is_valid_bin}")

    except Exception as e:
        print(f"Errore nel test binario: {e}")