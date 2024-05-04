import socketio
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from .utils import ENCRYPT_X3DH, DECRYPT_X3DH, GENERATE_DH, DH, KDF_RK, RatchetEncrypt, RatchetDecrypt, Header
import base64
import argparse



SERVER = 'http://localhost:8080'

sio = socketio.Client(logger=True)
sio.connect(SERVER)

def serialize(val):
    return base64.standard_b64encode(val).decode('utf-8')

def deserialize(val):
    return base64.standard_b64decode(val.encode('utf-8'))

class User():
    def __init__(self, username):
        self.username = username
        self.sessions = {}
        self.x3dh_session = {}
        self.ratchet_session = {}
        self.messages = {}
        self.generate_user()

    def init_ratchet_transmission(self, username):
        self.messages[username] = []
        # alice ka code
        SK = self.x3dh_session[username]['sk']
        self.ratchet_session[username] = {}
        recipient_dh_pk = self.x3dh_session[username]['spk']
        self.ratchet_session[username]["DHs"] = GENERATE_DH()
        self.ratchet_session[username]["DHr"] = recipient_dh_pk
        self.ratchet_session[username]["RK"], self.ratchet_session[username]["CKs"] = KDF_RK(SK, DH(self.ratchet_session[username]["DHs"], self.ratchet_session[username]["DHr"]))
        self.ratchet_session[username]["RK"] = x25519.X25519PublicKey.from_public_bytes(self.ratchet_session[username]["RK"])
        self.ratchet_session[username]["CKs"] = x25519.X25519PublicKey.from_public_bytes(self.ratchet_session[username]["CKs"])
        self.ratchet_session[username]["CKr"] = None
        self.ratchet_session[username]["Ns"] = 0
        self.ratchet_session[username]["Nr"] = 0
        self.ratchet_session[username]["PN"] = 0
        self.ratchet_session[username]["MKSKIPPED"] = {}
    
    def init_ratchet_reciever(self, username):
        self.messages[username] = []
        SK = self.x3dh_session[username]['sk']
        recipient_dh_sk = self.x3dh_session[username]['spk']
        self.ratchet_session[username] = {}
        self.ratchet_session[username]["DHs"] = recipient_dh_sk
        self.ratchet_session[username]["DHr"] = None
        self.ratchet_session[username]["RK"] = SK
        self.ratchet_session[username]["CKs"] = None
        self.ratchet_session[username]["CKr"] = None
        self.ratchet_session[username]["Ns"] = 0
        self.ratchet_session[username]["Nr"] = 0
        self.ratchet_session[username]["PN"] = 0
        self.ratchet_session[username]["MKSKIPPED"] = {}

        pass

    def generate_user(self, opk_size=10):
        self.ik = x25519.X25519PrivateKey.generate()
        self.sik = ed25519.Ed25519PrivateKey.generate()
        self.spk = x25519.X25519PrivateKey.generate()
        spk_bytes = self.spk.public_key().public_bytes_raw()

        self.spk_sig = self.sik.sign(spk_bytes)

    def serialize_user(self):
        
        ik_bytes = self.ik.public_key().public_bytes_raw()
        sik_bytes = self.sik.public_key().public_bytes_raw()
        spk_bytes = self.spk.public_key().public_bytes_raw()
        
        return {
            "username": self.username, 
            "ik": serialize(ik_bytes),
            "sik": serialize(sik_bytes),
            "spk": serialize(spk_bytes),
            "spk_sig": serialize(self.spk_sig)
        }

    def register_user(self):
        user = self.serialize_user()
        return sio.call("register_user", user)
    def request_user_prekey_bundle(self, username):
        res = sio.call("request_prekey", {"username": username})
        if(not res[0]):
            raise Exception(f"User {username} not registered")
        data = res[1]
        ik_bytes = deserialize(data["ik"])
        sik_bytes = deserialize(data["sik"])
        spk_bytes = deserialize(data["spk"])
        spk_sig_bytes = deserialize(data["spk_sign"])
        
        ik = x25519.X25519PublicKey.from_public_bytes(ik_bytes)
        sik = ed25519.Ed25519PublicKey.from_public_bytes(sik_bytes)
        spk = x25519.X25519PublicKey.from_public_bytes(spk_bytes)

        try:
            sik.verify(spk_sig_bytes, spk_bytes)
        except:
            raise Exception("SPK verification failed")

        self.sessions[username] = {
            'ik': ik,
            'spk': spk
        }

    def send_message(self, username, msg):
        ad = self.x3dh_session[username]['ad']
        header, ciphertext = RatchetEncrypt(self.ratchet_session[username], msg.encode('utf-8'), ad.encode('utf-8'))
        ciphertext, mac = ciphertext
        self.messages[username].append((self.username, msg ))
        return sio.call("ratchet_msg", {'username': username,'cipher': serialize(ciphertext), 'header': header.serialize(), 'hmac': serialize(mac), 'from': self.username})
        
    def is_connected(self, username):
        if username in self.x3dh_session:
            return True
        else:
            return False
    def recieve_message(self, username, msg):
        header = Header.deserialize(msg['header'])
        ciphertext = deserialize(msg['cipher'])
        hmac = deserialize(msg['hmac'])
        ad = self.x3dh_session[username]['ad']
        plaintext = RatchetDecrypt(self.ratchet_session[username], header, (ciphertext, hmac), ad.encode('utf-8'))
        print("recv:", plaintext)
        self.messages[username].append((username, plaintext.decode('utf-8') ))
        return plaintext.decode('utf-8')

    def receive_x3dh(self, username, data):
        # print(data)
        # {"username": username, "from": self.username, "ik": serialize(ik_bytes), "epk": serialize(epk_pub_bytes), "cipher": ciphertext, "nonce":nonce}
        ika_bytes = deserialize(data["ik"])
        epk_bytes = deserialize(data["epk"])
        cipher = deserialize(data["cipher"])
        hmac = deserialize(data["hmac"])
        ika = x25519.X25519PublicKey.from_public_bytes(ika_bytes)
        epk = x25519.X25519PublicKey.from_public_bytes(epk_bytes)
        dh1 = self.spk.exchange(ika)
        dh2 = self.ik.exchange(epk)
        dh3 = self.spk.exchange(epk)

        info = b"extended_triple_diffie_hellman"
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00"*32,
            info=info,
        )
        
        f = b"\xff" * 32
        km = dh1 + dh2 + dh3
        SK = hkdf.derive(f + km)

        
        
        ad  = serialize(ika_bytes) +  serialize(self.ik.public_key().public_bytes_raw()) 
        res = DECRYPT_X3DH(SK, cipher, hmac, ad.encode('utf-8'))
        if(res[0]):
            self.x3dh_session[username] = {"sk" : SK, "spk": self.spk, "ad": ad}
            self.init_ratchet_reciever(username)
        else:
            print("DH Failed")
            return False
        
        return True
    def perform_x3dh(self, username):
        if(not username in self.sessions):
            print("User key bundles not requested!")
        self.epk = x25519.X25519PrivateKey.generate()
        dh1 = self.ik.exchange(self.sessions[username]['spk'])
        dh2 = self.epk.exchange(self.sessions[username]['ik'])
        dh3 = self.epk.exchange(self.sessions[username]['spk'])

        info = b"extended_triple_diffie_hellman"
    
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00"*32,
            info=info,
        )
        
        f = b"\xff" * 32
        km = dh1 + dh2 + dh3
        SK = hkdf.derive(f + km)

       
        self.epk_pub = self.epk.public_key()
        epk_pub_bytes = self.epk_pub.public_bytes_raw()
        ik_bytes = self.ik.public_key().public_bytes_raw()
        ik_b_bytes = self.sessions[username]['ik'].public_bytes_raw()
        del self.epk
        del dh1, dh2, dh3

        ad  = serialize(ik_bytes) + serialize(ik_b_bytes)
        msg = "##CHAT_START##"
        ciphertext, hmac = ENCRYPT_X3DH(SK, msg.encode('utf-8'), ad.encode('utf-8'))

        self.x3dh_session[username] = {"sk" : SK, "spk": self.sessions[username]['spk'], "ad": ad}
        res = sio.call("x3dh_message", {"username": username, "from": self.username, "ik": serialize(ik_bytes), "epk": serialize(epk_pub_bytes), "cipher": serialize(ciphertext), "hmac":serialize(hmac)})
        if res:
            self.init_ratchet_transmission(username)
        else:
            print("DH Failed!")
        return res



def reg_callback(user, msg_event=lambda x: x):
    @sio.on('x3dh_message')
    def on_x3dh_message(data):
        user.receive_x3dh(data["from"], data)
        return True

    @sio.on('ratchet_msg')
    def on_ratchet_msg(data):
        print(data)
        
        msg_event(user.recieve_message(data["from"], data))
        return True


if __name__ == "main":
    parser = argparse.ArgumentParser(description="Process username and boolean arguments")
    parser.add_argument("username", help="The username")
    parser.add_argument("--initiate", action="store_true", help="Boolean flag to indicate initiation")
    parser.add_argument("--target", help="The target username")

    args = parser.parse_args()
    user= User(args.username)
    user.register_user()
    if(args.initiate):
        user.request_user_prekey_bundle(args.target)
        user.perform_x3dh(args.target)
        print(user.send_message(args.target, "Hello"))
        user.send_message(args.target, "Bye")
        print("done")

        
    sio.wait()

