import eventlet
import socketio

sio = socketio.Server()
app = socketio.WSGIApp(sio)

@sio.event
def connect(sid, environ):
    print('connect ', sid)

@sio.event
def my_message(sid, data):
    print('message ', data)

@sio.event
def disconnect(sid):
    print('disconnect ', sid)

@sio.on('bob_message')
def bob_message(sid, data):
    print('message received with ', data)
    sio.emit('my response', {'response': 'my response'})

if __name__ == '__main__':
    eventlet.wsgi.server(eventlet.listen(('', 6969)), app)