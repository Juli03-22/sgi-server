import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

USERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "users"))
PRIVATE_KEY_FILE = os.path.join(USERS_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(USERS_DIR, "public_key.pem")

def generar_llaves():
    if not (os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE)):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def obtener_llaves():
    generar_llaves()
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def firmar_hash(hash_bytes):
    private_key, _ = obtener_llaves()
    firma = private_key.sign(
        hash_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return firma.hex()

def verificar_firma(hash_bytes, firma_hex):
    _, public_key = obtener_llaves()
    try:
        public_key.verify(
            bytes.fromhex(firma_hex),
            hash_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
