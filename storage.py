import json

def save_encrypted_json(data, filename, password):
    """
    Save data to an encrypted JSON file using Fernet symmetric encryption.
    """
    try:
        from cryptography.fernet import Fernet
        import base64
        from hashlib import sha256
    except ImportError:
        raise ImportError('cryptography package is required for encrypted storage.')
    key = base64.urlsafe_b64encode(sha256(password.encode()).digest())
    f = Fernet(key)
    enc = f.encrypt(json.dumps(data).encode())
    with open(filename, 'wb') as out:
        out.write(enc)

def load_encrypted_json(filename, password):
    """
    Load and decrypt an encrypted JSON file using Fernet symmetric encryption.
    """
    try:
        from cryptography.fernet import Fernet
        import base64
        from hashlib import sha256
    except ImportError:
        raise ImportError('cryptography package is required for encrypted storage.')
    key = base64.urlsafe_b64encode(sha256(password.encode()).digest())
    f = Fernet(key)
    with open(filename, 'rb') as inp:
        enc = inp.read()
    dec = f.decrypt(enc)
    return json.loads(dec.decode()) 