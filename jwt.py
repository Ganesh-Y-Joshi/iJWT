import json
from abc import ABC, abstractmethod
import hmac
import hashlib
from datetime import datetime, timedelta
import rsa
import base64
from enum import Enum
import yaml


def load_config(c):
    """
    The following functions loads the config file to
    python dictionary in yaml format

    Args:
        c: config yml file path

    Returns:
        dict
    """
    with open(c, "r") as f:
        return yaml.safe_load(f)


class BaseAlgorithm(ABC):

    @abstractmethod
    def build_keys(self):
        """
        Builds the cryptographic keys needed for the algorithm.

        Returns:
            Any: The keys needed for the algorithm.
        """
        pass

    @abstractmethod
    def sign(self, message, key):
        """
        Signs a message using the provided key.

        Args:
            message (str): The message to be signed.
            key (Any): The key to sign the message with.

        Returns:
            Any: The signature of the message.
        """
        pass

    @abstractmethod
    def verify_claims(self, message, signature, key):
        """
        Verifies the claims of a message using the provided key and signature.

        Args:
            message (str): The message to be verified.
            signature (Any): The signature to verify the message against.
            key (Any): The key to verify the message with.

        Returns:
            bool: True if the verification is successful, False otherwise.
        """
        pass

    @abstractmethod
    def s(self):
        """
        Returns the signing algorithm used

        Returns:
             str: The signing algorithm used for signing the tokens
        """
        pass


class HMACAlgorithm(BaseAlgorithm):

    def s(self):
        return "hmac"

    def __init__(self, key=None):
        """
        Initializes the HMACAlgorithm with an optional user-defined key.

        Args:
            key (bytes, optional): The user-defined key. If not provided, a key will be generated.
        """
        self.key = key or self.build_keys()

    def build_keys(self):
        """
        Generates a random key for HMAC if not provided.

        This method checks if a key was provided during initialization. If
        not, it generates a random key.

        Returns:
            bytes: The HMAC key (randomly generated if not provided).
        """
        return hashlib.sha256(self.key.encode()).digest()

    def sign(self, message, key=None):
        """
        Signs a message using HMAC and the provided or initialized key.

        Args:
            message (str): The message to be signed.
            key (bytes, optional): The key to sign the message with. If not provided, uses the initialized key.

        Returns:
            str: The HMAC signature of the message.
        """
        key = key or self.key
        return hmac.new(key, message.encode(), hashlib.sha256).digest()

    def verify_claims(self, message, signature, key=None):
        """
        Verifies the claims of a message using HMAC and the provided or initialized key.

        Args:
            message (str): The message to be verified.
            signature (str): The HMAC signature to verify the message against.
            key (bytes, optional): The key to verify the message with. If not provided, uses the initialized key.

        Returns:
            bool: True if the verification is successful, False otherwise.
        """
        key = key or self.key
        expected_signature = self.sign(message, key)
        return hmac.compare_digest(expected_signature, signature)


class RSAKeys:
    def __init__(self, pub_key, pvt_key):
        """
        Initializes the RSAKeys with the given public and private keys.

        Args:
            pub_key (rsa.PublicKey): The RSA public key.
            pvt_key (rsa.PrivateKey): The RSA private key.
        """
        self.pub_key = pub_key
        self.pvt_key = pvt_key

    @staticmethod
    def generate_keys(key_size=2048):
        """
        Generates a new pair of RSA keys.

        Args:
            key_size (int, optional): The size of the RSA keys to generate. Defaults to 2048.

        Returns:
            RSAKeys: The generated RSA public and private keys.
        """
        (pub_key, pvt_key) = rsa.newkeys(key_size)
        return RSAKeys(pub_key, pvt_key)


class RSAAlgorithm(BaseAlgorithm):
    def __init__(self, _rsa: RSAKeys):
        self.pub = _rsa.pub_key
        self.pvt = _rsa.pvt_key

    def s(self):
        return "rsa"

    def build_keys(self):
        """
        Generates a new pair of RSA keys.

        Returns:
            RSAKeys: The generated RSA public and private keys.
        """
        return RSAKeys.generate_keys()

    def sign(self, message, pvt_key=None):
        """
        Signs a message using RSA and the provided private key.

        Args:
            message (str | bytes): The message to be signed.
            pvt_key (rsa.PrivateKey): The RSA private key to sign the message with.

        Returns:
            bytes: The RSA signature of the message.
        """
        pvt_key = pvt_key if pvt_key is not None else self.pvt
        return rsa.sign(message.encode(), pvt_key, 'SHA-256')

    def verify_claims(self, message, signature, pub_key):
        """
        Verifies the claims of a message using RSA and the provided public key and signature.

        Args:
            message (str): The message to be verified.
            signature (bytes): The RSA signature to verify the message against.
            pub_key (rsa.PublicKey): The RSA public key to verify the message with.

        Returns:
            bool: True if the verification is successful, False otherwise.
        """
        try:
            pub_key = pub_key if pub_key is not None else self.pub
            rsa.verify(message.encode(), signature, pub_key)
            return True
        except rsa.VerificationError:
            return False


class AlgorithmFactory:
    @staticmethod
    def get(t, pub, pvt):
        """
        Factory method to get the type of the type of the Signing algorithm required
        whether HMAC or RSA

        Args:
              t: the type of algorithm required
              pvt: the private key
              pub Optional: the private key

        Returns:
            BaseAlgorithm with required config
        """
        if t == "rsa":
            if pvt is not None and pub is not None:
                return RSAAlgorithm(RSAKeys(pub_key=pub, pvt_key=pvt))
        if t == "hmac":
            if pvt is not None:
                return HMACAlgorithm(pvt)


def base64url_decode(input):
    """
    Decodes a base64 URL-safe encoded input.

    This function adds the necessary padding ('=') to the input if its length
    is not a multiple of 4, and then decodes it using base64 URL-safe decoding.

    Args:
        input (bytes): The base64 URL-safe encoded input to be decoded.

    Returns:
        bytes: The decoded output.
    """
    rem = len(input) % 4
    if rem > 0:
        input += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(input)


def base64url_encode(input):
    """
    Encodes input using base64 URL-safe encoding.

    This function encodes the input using base64 URL-safe encoding and
    removes any padding ('=') from the encoded output.

    Args:
        input (bytes): The input to be encoded.

    Returns:
        bytes: The base64 URL-safe encoded output without padding.
    """
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


class JwtStatus(Enum):
    VALID_OK = 200
    INVALID = 400
    EXPIRED = 401

    """
    Enum for JWT status codes.

    This enum defines status codes for JSON Web Token (JWT) validation.

    Attributes:
        VALID_OK (int): Status code for a valid JWT (200).
        INVALID (int): Status code for an invalid JWT (400).
        EXPIRED (int): Status code for an expired JWT (401).
    """


class JreEncryption(ABC):

    @abstractmethod
    def encrypt(self, claims, key):
        """
        Encrypts the given claims using the provided key.

        Args:
            claims (str): The claims to be encrypted.
            key (Any): The key to encrypt the claims with.

        Returns:
            bytes: The encrypted claims.
        """
        pass

    @abstractmethod
    def decrypt(self, encrypted, key):
        """
        Decrypts the given encrypted data using the provided key.

        Args:
            encrypted (bytes): The encrypted data to be decrypted.
            key (Any): The key to decrypt the data with.

        Returns:
            str: The decrypted claims.
        """
        pass

    @abstractmethod
    def s(self):
        pass


class RSAEncryption(JreEncryption):

    def s(self):
        return "rsa"

    def encrypt(self, claims, pvt_key):
        """
        Encrypts the given claims using the provided RSA public key.

        Args:
            claims (str): The claims to be encrypted.
            pub_key (rsa.PublicKey): The RSA public key to encrypt the claims with.

        Returns:
            bytes: The encrypted claims.
        """
        return rsa.encrypt(claims.encode(), pvt_key)

    def decrypt(self, encrypted, pub_key):
        """
        Decrypts the given encrypted data using the provided RSA private key.

        Args:
            encrypted (bytes): The encrypted data to be decrypted.
            pvt_key (rsa.PrivateKey): The RSA private key to decrypt the data with.

        Returns:
            str: The decrypted claims.
        """
        return rsa.decrypt(encrypted, pub_key).decode()


class JwtBuilder:
    def __init__(self, jre: JreEncryption, claims: dict, signing_key, encrypting_key, signing: BaseAlgorithm):
        """
        Initializes the JwtBuilder with the provided encryption, claims, signing key, encryption key, and signing algorithm.

        Args:
            jre (JreEncryption): The encryption method for JWT claims.
            claims (dict): The claims to be included in the JWT.
            signing_key (Any): The key to sign the JWT with.
            encrypting_key (Any): The key to encrypt the claims with.
            signing (BaseAlgorithm): The signing algorithm for the JWT.
        """
        if isinstance(jre, JreEncryption):
            self.jre = jre
        if isinstance(claims, dict):
            self.claims = claims
        if isinstance(signing, BaseAlgorithm):
            self.signing = signing

        self.signing_key = signing_key
        self.encrypting_key = encrypting_key

        header = {
            "typ": "JWT",
            "alg": signing.s(),
            "enc": jre.s(),
            "first_access_time": datetime.now().isoformat(),
        }

        self.header = base64url_encode(json.dumps(header).encode()).decode()

        eclaims = jre.encrypt(json.dumps(claims), encrypting_key)
        self.encrypted_claims = base64url_encode(eclaims).decode()

        sign = signing.sign(f"{self.header}.{self.encrypted_claims}", signing_key)
        self.signature = base64url_encode(sign).decode()

    def build(self):
        """
        Builds the JWT by concatenating the encoded header, encrypted claims, and signature.

        Returns:
            str: The complete JWT as a string.
        """
        return f"{self.header}.{self.encrypted_claims}.{self.signature}"


def is_valid(token: str, signing_alg: str, spub_key, expiry_interval, spvt_key):
    header, encrypted_claims, signature = token.split('.')
    alg = AlgorithmFactory.get(signing_alg, pvt=spvt_key, pub=spub_key)
    if not alg.verify_claims(f"{header}.{encrypted_claims}", base64url_decode(signature.encode()), spub_key):
        return None, None, JwtStatus.INVALID
    decoded_header: dict = json.loads(base64url_decode(header.encode()))
    d = datetime.now() - datetime.fromisoformat(decoded_header.get("first_access_time"))
    if d.seconds - expiry_interval > 0:
        return None, None, JwtStatus.EXPIRED
    return decoded_header, encrypted_claims, JwtStatus.VALID_OK


class SingletonEncryptor:
    _rsa = None

    @classmethod
    def get(cls):
        if cls._rsa is None:
            return RSAEncryption()
        return cls._rsa


def decode_claims(token: str, signing_alg: str, spub_key, ekey, expiry_interval, spvt_key=None):
    h, c, s = is_valid(token, signing_alg, spvt_key, expiry_interval, spub_key)
    if s == JwtStatus.VALID_OK:
        return s, json.loads(SingletonEncryptor.get().decrypt(base64url_decode(c.encode()), ekey))
    else:
        return s, {}


# Example Usage
# def main():
#     claims = {
#         "sub": "1234567890",
#         "name": "John Doe",
#         "admin": True
#     }
# 
#     rsa_keys = RSAKeys.generate_keys()
#     e_keys = RSAKeys.generate_keys()
# 
#     rsa_encryption = RSAEncryption()
#     rsa_signing = RSAAlgorithm(RSAKeys(rsa_keys.pub_key, rsa_keys.pvt_key))
# 
#     jwt_builder = JwtBuilder(
#         jre=rsa_encryption,
#         claims=claims,
#         signing_key=rsa_signing.pvt,
#         encrypting_key=e_keys.pub_key,
#         signing=rsa_signing
#     )
# 
#     jwt_token = jwt_builder.build()
#     print("Generated JWT Token:")
#     print(jwt_token)
#     print(decode_claims(jwt_token, "rsa", rsa_keys.pub_key, e_keys.pvt_key, 1000, rsa_keys.pvt_key))
# 
# 
# if __name__ == "__main__":
#     main()
