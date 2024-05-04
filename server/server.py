from tinydb import TinyDB, Query
import eventlet
import socketio

db = TinyDB('user_keys.json')
db.truncate()

def create_user_schema(username, ik, sik, spk, spk_sign):
    return {"username": username, "ik": ik, "sik": sik, "spk": spk, "spk_sign": spk_sign}


def find_user(username):
    query = Query()
    res = db.search(query.username == username)
    if len(res):
        return (True, res[0])
    else:
        return (False, None)


def update_user(username, user):
    query = Query()
    db.update(user, query.username == username)


def add_user(username, ik, sik, spk, spk_sign):
    user_json = create_user_schema(username, ik, sik, spk, spk_sign)
    if (find_user(username)[0]):
        update_user(username, user_json)
    else:
        db.insert(user_json)

def update_user_spk(username, spk, spk_sign):
    res = find_user(username)
    if (not res[0]):
        raise Exception(f"User {username} not found!")

    user = res[1]

    res['spk'] = spk
    res['spk_sign'] = spk_sign

    update_user(username, user)


def request_prekey(username):
    res = find_user(username)
    if (not res[0]):
        raise Exception(f"User {username} not found!")

    user = res[1]

    return {"ik": user['ik'], "sik": user['sik'], "spk": user['spk'], "spk_sign": user['spk_sign']}

sio = socketio.Server()
app = socketio.WSGIApp(sio)

user_map = {}
@sio.event
def connect(sid, environ):
    print('connect ', sid)

@sio.on('register_user')
def on_register_user(sid, data):
    user_map[data["username"]] = sid
    add_user(data["username"], data["ik"],  data["sik"], data["spk"], data["spk_sig"])
    return True

@sio.on('request_prekey')
def on_request_prekey(sid, data):
    try:
        prekey_bundle = request_prekey(data["username"])
    except:
        return (False, {})
    return (True, prekey_bundle)

@sio.on('x3dh_message')
def on_x3dh_message(sid, data):
    if not data['username'] in user_map:
        return False
    
    res = sio.call('x3dh_message', data, sid=user_map[data['username']])
    return res


@sio.on('msg_topic')
def on_msg_topic(sid, data):
    if not data['username'] in user_map:
        return False
    print("um:",user_map)
    res = sio.emit('msg_topic', data)
    return "sankalp"

@sio.event
def disconnect(sid):
    print('disconnect ', sid)

@sio.on('bob_message')
def bob_message(sid, data):
    print('message received with ', data)

    sio.emit('callback', {'message': 'Callback received'}, room=sid)
if __name__ == '__main__':
    eventlet.wsgi.server(eventlet.listen(('', 6969)), app)