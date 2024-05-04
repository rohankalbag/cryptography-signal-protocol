import socketio
SERVER = 'http://localhost:6969'
sio = socketio.Client(logger=True)

@sio.event
def connect():
    print('connection established')

@sio.event
def disconnect():
    print('disconnected from server')

@sio.on('my response')
def bob_message_resp(data):
    print('message received with ', data)

sio.connect(SERVER)
sio.emit('bob_message', {'foo': 'bar'})
sio.wait()