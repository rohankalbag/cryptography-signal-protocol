import socketio

class Header:
    def __init__(self, dh, pn, n):
        self.dh = dh
        self.pn = pn
        self.n = n

class Person():
    def __init__(self, username):
        self.username = username
        self.personal_state = None
    
    def encrypt(self, plaintext):
        # TODO: Implement encryption
        header = Header(b'a'*32, 1, 1)
        ciphertext = plaintext
        return (header, ciphertext)
    
    def sendMessage(self, to, plaintext):
        header, ciphertext = self.encrypt(plaintext)
        sio.emit('message', {'to_user':to, 'header': header, 'message': ciphertext})

USER_NAME = 'alice'
SERVER = 'http://localhost:6969'

sio = socketio.Client()

@sio.event
def connect():
    print('connection established')

@sio.event
def disconnect():
    print('disconnected from server')

@sio.on('message_response')
def message_recvd_from_server(data):
    print(data)

if __name__ == '__main__':
    alice = Person(USER_NAME)
    sio.connect(SERVER)

    alice.sendMessage('bob', 'Hello Bob!')
    sio.wait()