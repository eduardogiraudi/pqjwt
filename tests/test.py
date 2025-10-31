import pytest
import os
import json
import time
import tempfile
import shutil
import warnings
from app import JWTManager, JWTKeyManager, create_publisher, create_consumer
import errors

class TestJWTPostQuantum:
    def setup_method(self):
        """Setup per ogni test"""
        self.test_dir = tempfile.mkdtemp()
        self.test_keys_dir = os.path.join(self.test_dir, "keys")
        os.makedirs(self.test_keys_dir, exist_ok=True)

    def teardown_method(self):
        """Cleanup dopo ogni test"""
        shutil.rmtree(self.test_dir)

    def test_supported_algorithms(self):
        """Test che verifica gli algoritmi supportati"""
        algs = JWTKeyManager.get_supported_algorithms()
        assert isinstance(algs, list)
        assert len(algs) > 0
        assert "ML-DSA-44" in algs
        assert "Falcon-512" in algs
        assert "SPHINCS+-SHA2-128f-simple" in algs

    def test_jwt_header_mapping(self):
        """Test mapping tra nomi algoritmo e header JWT"""
        assert JWTKeyManager.get_jwt_header_name("ML-DSA-44") == "Dilithium2"
        assert JWTKeyManager.get_jwt_header_name("Falcon-512") == "Falcon512"
        
        # Test reverse mapping
        assert JWTKeyManager.get_algorithm_from_jwt_header("Dilithium2") == "ML-DSA-44"
        assert JWTKeyManager.get_algorithm_from_jwt_header("Falcon512") == "Falcon-512"

    def test_algorithm_not_supported_error(self):
        """Test eccezione per algoritmo non supportato"""
        with pytest.raises(errors.AlgorithmNotSupportedError):
            JWTKeyManager.get_jwt_header_name("INVALID-ALG")
        
        with pytest.raises(errors.AlgorithmNotSupportedError):
            JWTKeyManager.get_algorithm_from_jwt_header("InvalidHeader")

    def test_key_format_detection(self):
        """Test rilevamento automatico formato chiavi"""
        # Test estensioni file
        assert JWTKeyManager._detect_format("key.pem") == "pem"
        assert JWTKeyManager._detect_format("key.pub") == "pub"
        assert JWTKeyManager._detect_format("key.bin") == "bin"
        
        # Test contenuto PEM
        test_pem = "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----"
        pem_file = os.path.join(self.test_dir, "test_key")
        with open(pem_file, "w") as f:
            f.write(test_pem)
        assert JWTKeyManager._detect_format(pem_file) == "pem"

    def test_publisher_key_generation(self):
        """Test generazione chiavi per publisher"""
        for algorithm in ["ML-DSA-44", "Falcon-512", "SPHINCS+-SHA2-128f-simple"]:
            publisher = JWTManager(
                mode="publisher", 
                key_dir=self.test_keys_dir,
                algorithm=algorithm,
                key_format="pem"
            )
            
            assert publisher.public_key is not None
            assert publisher.secret_key is not None
            assert len(publisher.public_key) > 0
            assert len(publisher.secret_key) > 0
            
            # Verifica che i file siano stati creati
            public_key_path = os.path.join(self.test_keys_dir, f"{algorithm.lower()}_public.pem")
            private_key_path = os.path.join(self.test_keys_dir, f"{algorithm.lower()}_private.pem")
            
            assert os.path.exists(public_key_path)
            assert os.path.exists(private_key_path)

    def test_consumer_key_loading(self):
        """Test caricamento chiavi per consumer"""
        # Prima crea le chiavi con un publisher
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # Poi carica come consumer
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        assert consumer.public_key is not None
        assert consumer.secret_key is None  # Consumer non ha chiave privata
        assert consumer.public_key == publisher.public_key

    def test_consumer_missing_key_error(self):
        """Test eccezione quando manca chiave pubblica per consumer"""
        with pytest.raises(FileNotFoundError):
            create_consumer(
                key_dir=self.test_keys_dir,
                algorithm="ML-DSA-44"
            )

    def test_jwt_encoding_decoding(self):
        """Test codifica e decodifica JWT"""
        test_payload = {
            "sub": "user123",
            "name": "Test User",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        
        for algorithm in ["ML-DSA-44", "Falcon-512"]:  # Test con algoritmi più veloci
            publisher = create_publisher(
                key_dir=self.test_keys_dir,
                algorithm=algorithm
            )
            
            consumer = create_consumer(
                key_dir=self.test_keys_dir,
                algorithm=algorithm
            )
            
            # Codifica JWT
            jwt_token = publisher.encode(test_payload)
            assert jwt_token is not None
            assert len(jwt_token.split('.')) == 3
            
            # Decodifica e verifica
            headers, payload = consumer.decode(jwt_token)
            
            # Verifica payload
            assert payload["sub"] == test_payload["sub"]
            assert payload["name"] == test_payload["name"]
            
            # Verifica headers
            assert headers["alg"] == JWTKeyManager.get_jwt_header_name(algorithm)
            assert headers["typ"] == "JWT"

    def test_jwt_expiration(self):
        """Test verifica scadenza JWT"""
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # JWT scaduto
        expired_payload = {
            "sub": "user123",
            "exp": int(time.time()) - 3600  # Scaduto 1 ora fa
        }
        
        expired_jwt = publisher.encode(expired_payload)
        
        with pytest.raises(errors.JWTExpiredError):
            consumer.decode(expired_jwt)

    def test_jwt_not_before(self):
        """Test verifica claim 'nbf' (not before)"""
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # JWT non ancora valido
        future_payload = {
            "sub": "user123",
            "nbf": int(time.time()) + 3600,  # Valido tra 1 ora
            "exp": int(time.time()) + 7200
        }
        
        future_jwt = publisher.encode(future_payload)
        
        with pytest.raises(errors.JWTValidationError) as exc_info:
            consumer.decode(future_jwt)
        assert "nbf" in str(exc_info.value)

    def test_jwt_invalid_signature(self):
        """Test verifica firma JWT non valida"""
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # Crea JWT valido
        valid_jwt = publisher.encode({"test": "data"})
        
        # Modifica la firma per renderla non valida
        parts = valid_jwt.split('.')
        tampered_jwt = f"{parts[0]}.{parts[1]}.tampered_signature"
        
        with pytest.raises(errors.JWTSignatureError):
            consumer.decode(tampered_jwt)

    def test_jwt_malformed_token(self):
        """Test token JWT malformato"""
        # Prima crea le chiavi necessarie
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # Token con parti mancanti - dovrebbe sollevare JWTValidationError
        with pytest.raises(errors.JWTValidationError) as exc_info:
            consumer.decode("invalid.token")
        assert "wrong_number_of_parts" in str(exc_info.value)
        
        # Token con formato valido ma contenuto non valido
        # Creiamo un token con 3 parti valide ma con JSON non valido nel payload
        import base64
        
        # Header valido
        header = base64.urlsafe_b64encode(json.dumps({"alg": "Dilithium2", "typ": "JWT"}).encode()).decode().rstrip('=')
        # Payload non valido (non è JSON valido)
        payload = base64.urlsafe_b64encode(b"invalid json {").decode().rstrip('=')
        # Firma casuale
        signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip('=')
        
        invalid_json_jwt = f"{header}.{payload}.{signature}"
        
        with pytest.raises(errors.JWTDecodeError):
            consumer.decode(invalid_json_jwt)

    def test_permission_error_publisher_only(self):
        """Test che solo i publisher possono firmare JWT"""
        # Prima crea le chiavi necessarie
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        with pytest.raises(PermissionError):
            consumer.encode({"test": "data"})

    def test_key_export_formats(self):
        """Test esportazione chiavi in diversi formati"""
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # Test diversi formati di output
        public_bytes = publisher.get_public_key("bytes")
        public_hex = publisher.get_public_key("hex")
        public_pem = publisher.get_public_key("pem")
        
        assert isinstance(public_bytes, bytes)
        assert isinstance(public_hex, str)
        assert isinstance(public_pem, str)
        assert "BEGIN PUBLIC KEY" in public_pem
        
        # Test esportazione file
        export_path = os.path.join(self.test_dir, "exported_key.pub")
        publisher.export_public_key(export_path, "pub")
        assert os.path.exists(export_path)

    def test_key_save_load_formats(self):
        """Test salvataggio e caricamento chiavi in diversi formati"""
        test_algorithm = "ML-DSA-44"
        
        for format_type in ["pem", "pub", "bin"]:
            # Genera e salva chiavi
            publisher = JWTManager(
                mode="publisher",
                key_dir=self.test_keys_dir,
                algorithm=test_algorithm,
                key_format=format_type
            )
            
            # Ricarica le chiavi
            public_key_path = os.path.join(
                self.test_keys_dir, 
                f"{test_algorithm.lower()}_public.{format_type if format_type != 'pub' else 'pub'}"
            )
            
            loaded_key, loaded_alg = JWTKeyManager.load_key(
                public_key_path, 
                format_type, 
                "public"
            )
            
            assert loaded_key == publisher.public_key
            assert loaded_alg == test_algorithm

    def test_key_format_error(self):
        """Test eccezioni per formato chiave non supportato"""
        with pytest.raises(errors.KeyFormatError):
            JWTManager(
                mode="publisher",
                key_dir=self.test_keys_dir,
                key_format="invalid_format",
                algorithm="ML-DSA-44"
            )
        
        with pytest.raises(errors.KeyFormatError):
            JWTKeyManager.save_key(b"test", "test.key", "invalid_format", "public")

    def test_crypto_key_error(self):
        """Test eccezioni relative alle chiavi crittografican"""
        # Test senza chiave privata
        publisher = JWTManager(
            mode="publisher",
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # Simula perdita chiave privata
        publisher.secret_key = None
        
        with pytest.raises(errors.CryptoKeyError):
            publisher.encode({"test": "data"})

    def test_algorithm_mismatch_warning(self):
        """Test gestione mismatch algoritmi"""
        # Crea JWT con un algoritmo
        publisher1 = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        jwt_token = publisher1.encode({"test": "data"})
        
        # Crea consumer con stesso algoritmo per caricare la chiave pubblica
        consumer_same_alg = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # Ora cambia l'algoritmo nel consumer (dopo che ha caricato la chiave)
        # e testa che venga stampato un warning quando si decodifica
        consumer_same_alg.algorithm = "Falcon-512"
        
        # Dovrebbe funzionare ma mostrare un messaggio di warning (print, non Python warning)
        # Testiamo che la decodifica funzioni comunque
        headers, payload = consumer_same_alg.decode(jwt_token)
        assert payload["test"] == "data"

    def test_verify_method(self):
        """Test metodo verify senza decodifica completa"""
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        valid_jwt = publisher.encode({"test": "data"})
        
        # Test verifica positiva
        assert consumer.verify(valid_jwt) == True
        
        # Test verifica negativa
        invalid_jwt = "invalid.token.signature"
        assert consumer.verify(invalid_jwt) == False

    def test_clock_skew_handling(self):
        """Test gestione clock skew per claim temporali"""
        publisher = create_publisher(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        consumer = create_consumer(
            key_dir=self.test_keys_dir,
            algorithm="ML-DSA-44"
        )
        
        # JWT che diventerà valido tra poco (entro lo skew)
        nbf_time = int(time.time()) + 3  # 3 secondi nel futuro
        
        payload = {
            "sub": "user123",
            "nbf": nbf_time,
            "exp": nbf_time + 3600
        }
        
        jwt_token = publisher.encode(payload)
        
        # Con skew default (5 secondi) dovrebbe passare
        headers, payload = consumer.decode(jwt_token, clock_skew=5)
        assert payload["sub"] == "user123"
        
        # Con skew minore dovrebbe fallire
        with pytest.raises(errors.JWTValidationError):
            consumer.decode(jwt_token, clock_skew=1)

    def test_all_algorithms_compatibility(self):
        """Test compatibilità con tutti gli algoritmi supportati"""
        # Test con un subset rappresentativo per velocità
        test_algorithms = [
            "ML-DSA-44",      # Dilithium2
            "Falcon-512",     # Falcon512  
            "SPHINCS+-SHA2-128f-simple"  # Sphincs
        ]
        
        for algorithm in test_algorithms:
            # Setup - usa directory separata per ogni algoritmo
            algo_keys_dir = os.path.join(self.test_keys_dir, algorithm)
            os.makedirs(algo_keys_dir, exist_ok=True)
            
            publisher = create_publisher(
                key_dir=algo_keys_dir,
                algorithm=algorithm
            )
            
            consumer = create_consumer(
                key_dir=algo_keys_dir, 
                algorithm=algorithm
            )
            
            # Test encoding/decoding
            test_payload = {"algorithm": algorithm, "timestamp": time.time()}
            jwt_token = publisher.encode(test_payload)
            
            headers, decoded_payload = consumer.decode(jwt_token)
            
            # Verifiche
            assert decoded_payload["algorithm"] == algorithm
            assert headers["alg"] == JWTKeyManager.get_jwt_header_name(algorithm)

    def test_error_messages_detail(self):
        """Test che i messaggi di errore contengano informazioni dettagliate"""
        # Test AlgorithmNotSupportedError
        try:
            JWTKeyManager.get_jwt_header_name("INVALID")
            assert False, "Dovrebbe sollevare eccezione"
        except errors.AlgorithmNotSupportedError as e:
            assert "INVALID" in str(e)
            assert "Supported" in str(e)
        
        # Test JWTExpiredError
        publisher = create_publisher(key_dir=self.test_keys_dir)
        expired_jwt = publisher.encode({"exp": time.time() - 3600})
        consumer = create_consumer(key_dir=self.test_keys_dir)
        
        try:
            consumer.decode(expired_jwt)
            assert False, "Dovrebbe sollevare eccezione"
        except errors.JWTExpiredError as e:
            assert "expired" in str(e).lower()

def test_standalone_functions():
    """Test delle funzioni standalone create_publisher e create_consumer"""
    with tempfile.TemporaryDirectory() as temp_dir:
        keys_dir = os.path.join(temp_dir, "keys")
        
        # Test create_publisher
        publisher = create_publisher(key_dir=keys_dir, algorithm="ML-DSA-44")
        assert publisher.mode == "publisher"
        assert publisher.public_key is not None
        assert publisher.secret_key is not None
        
        # Test create_consumer  
        consumer = create_consumer(key_dir=keys_dir, algorithm="ML-DSA-44")
        assert consumer.mode == "consumer"
        assert consumer.public_key is not None
        assert consumer.secret_key is None
        
        # Test che le chiavi siano compatibili
        jwt = publisher.encode({"test": "data"})
        headers, payload = consumer.decode(jwt)
        assert payload["test"] == "data"

if __name__ == "__main__":
    # Esegui i test
    pytest.main([__file__, "-v", "--tb=short"])