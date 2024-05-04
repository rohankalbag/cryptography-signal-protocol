from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import x25519


if __name__ == "__main__":
    
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_bytes = sk.private_bytes_raw()
    pk_bytes = pk.public_bytes_raw()
    
    sk_ed25519 = x25519.X25519PrivateKey.from_private_bytes(sk_bytes)
    pk_ed25519 = sk_ed25519.public_key()

    sk_ed25519_bytes = sk_ed25519.private_bytes_raw()
    
    pk_ed25519_bytes = pk_ed25519.public_bytes_raw( )


    print("Private key:", sk_bytes)
    print("Public key:", pk_bytes)
    print("Ed25519 Private key:", sk_ed25519_bytes)
    print("Ed25519 Public key:", pk_ed25519_bytes)

    assert sk_bytes == sk_ed25519_bytes
    for i in range(len(pk_bytes)):
        print(pk_bytes[i] == pk_ed25519_bytes[i])
    print(len(pk_bytes) == pk_ed25519_bytes[i])

    