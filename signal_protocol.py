from cryptography.hazmat.primitives.asymmetric import x25519
from XEdDSA import sign


class User():

    def __init__(self, name, MAX_OPK_NUM):
        self.name = name
        self.IK_s = x25519.X25519PrivateKey.generate()
        self.IK_p = self.IK_s.public_key()
        # Bob only needs to upload his identity key to the server once. However, Bob may upload new one-time prekeys at other times
        self.SPK_s = x25519.X25519PrivateKey.generate()
        self.SPK_p = self.SPK_s.public_key()
        self.SPK_sig = sign(self.IK_s, self.SPK_p)
        # Bob will also upload a new signed prekey and prekey signature at some interval (e.g. once a week, or once a month)
        # After uploading a new signed prekey, Bob may keep the private key corresponding to the previous signed prekey around for some period of time, to handle messages using it that have been delayed in transit. Eventually, Bob should delete this private key for forward secrecy
        self.OKPs = []
        self.OPKs_p = []
        for _ in range(MAX_OPK_NUM):
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            self.OPKs_p.append(pk)
            self.OKPs.append((sk, pk))
            # for later steps
            self.key_bundles = {}
            self.dr_keys = {}


    def publish(self):
        return {
            'IK_p': self.IK_p,
            'SPK_p': self.SPK_p,
            'SPK_sig': self.SPK_sig,
            'OPKs_p': self.OPKs_p
        }