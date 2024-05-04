from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


MAX_SKIP = 10

def GENERATE_DH():
    sk = x25519.X25519PrivateKey.generate()
    return sk

def DH(dh_pair, dh_pub):
    dh_out = dh_pair.exchange(dh_pub)
    return dh_out

def KDF_RK(rk, dh_out):
    # rk is hkdf salt, dh_out is hkdf input key material

    if isinstance(rk, x25519.X25519PublicKey):
        rk_bytes = rk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        rk_bytes = rk

    info = b"kdf_rk_info" # should be changed in other places HKDF() is used
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk_bytes,
        info=info,
    )
    
    h_out = hkdf.derive(dh_out)
    root_key = h_out[:32]
    chain_key = h_out[32:]

    return (root_key, chain_key)


def KDF_CK(ck):

    if isinstance(ck, x25519.X25519PublicKey):
        ck_bytes = ck.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        ck_bytes = ck

    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x01]))
    message_key = h.finalize()

    h = hmac.HMAC(ck_bytes, hashes.SHA256())
    h.update(bytearray([0x02]))
    next_ck = h.finalize()

    return (next_ck, message_key)

class Header:
    def __init__(self, dh, pn, n):
        self.dh = dh
        self.pn = pn
        self.n = n

def HEADER(dh_pair, pn, n):
    pk = dh_pair.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return Header(pk_bytes, pn.to_bytes(pn.bit_length()), n.to_bytes(n.bit_length()))

def CONCAT(ad, header):
    return (ad, header)
    
def ENCRYPT(mk, plaintext, associated_data):
    info = b"encrypt_info_kdf" # should be changed in other places HKDF() is used
    zero_filled = b"\x00"*80
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    assoc_data = ad + pk + pn + n

    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()

    h = hmac.HMAC(auth_key, hashes.SHA256())
    h.update(padded_assoc_data + ciphertext)
    h_out = h.finalize()
    return (ciphertext, h_out)


def DECRYPT(mk, cipherout, associated_data):
    
    ciphertext = cipherout[0]
    mac = cipherout[1]

    info = b"encrypt_info_kdf" # should be changed in other places HKDF() is used
    zero_filled = b"\x00"*80
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=zero_filled,
        info=info,
    )

    hkdf_out = hkdf.derive(mk)
    enc_key = hkdf_out[:32]
    auth_key = hkdf_out[32:64]
    iv = hkdf_out[64:]

    cipher = Cipher(algorithms.AES256(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    h = hmac.HMAC(auth_key, hashes.SHA256())
    
    ad, header = associated_data
    pk, pn, n = header.dh, header.pn, header.n
    assoc_data = ad + pk + pn + n
    
    padder = padding.PKCS7(256).padder()
    padded_assoc_data = padder.update(assoc_data) + padder.finalize()

    h.update(padded_assoc_data + ciphertext) 
    
    try:
        h.verify(mac)
    except:
        raise Exception("MAC verification failed")

    return plaintext
    

def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr)) 
    state.RK = x25519.X25519PublicKey.from_public_bytes(state.RK)
    state.CKs = x25519.X25519PublicKey.from_public_bytes(state.CKs)
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

def RatchetInitBob(state, SK, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}

def RatchetEncrypt(state, plaintext, AD):
    state.CKs, mk = KDF_CK(state.CKs)
    header = HEADER(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))

def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    if x25519.X25519PublicKey.from_public_bytes(header.dh) != state.DHr:                 
        SkipMessageKeys(state, int.from_bytes(header.pn))
        DHRatchet(state, header)
    SkipMessageKeys(state, int.from_bytes(header.n))             
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1
    padded_plain_text = DECRYPT(mk, ciphertext, CONCAT(AD, header))
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(padded_plain_text) + unpadder.finalize()

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, int.from_bytes(header.n)) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, int.from_bytes(header.n)]
        del state.MKSKIPPED[header.dh, int.from_bytes(header.n)]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None

def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Exception("Too many skipped messages")
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            DHr_bytes = state.DHr.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            state.MKSKIPPED[DHr_bytes, state.Nr] = mk
            state.Nr += 1

def DHRatchet(state, header):
    state.PN = state.Ns                          
    state.Ns = 0
    state.Nr = 0
    state.DHr = x25519.X25519PublicKey.from_public_bytes(header.dh)
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))


class PersonState():
    def __init__(self):
        self.DHs = None
        self.DHr = None
        self.RK = None
        self.CKs = None
        self.CKr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = {}

if __name__ == "__main__":
    alice = PersonState()
    bob = PersonState()

    ad_from_x3dh = b"a"*32
    sk_from_x3dh = x25519.X25519PrivateKey.generate().public_key()
    bob_spk_s = x25519.X25519PrivateKey.generate()
    bob_spk_p = bob_spk_s.public_key()

    RatchetInitAlice(alice, sk_from_x3dh, bob_spk_p)
    RatchetInitBob(bob, sk_from_x3dh, bob_spk_s)

    header, ciphertext = RatchetEncrypt(alice, b"hello", ad_from_x3dh)
    plaintext = RatchetDecrypt(bob, header, ciphertext, ad_from_x3dh)

    print(plaintext)

    header, ciphertext = RatchetEncrypt(alice, b"niggesh", ad_from_x3dh)
    plaintext = RatchetDecrypt(bob, header, ciphertext, ad_from_x3dh)
    
    print(plaintext)
