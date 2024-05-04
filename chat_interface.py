import sys
from PySide6.QtWidgets import QApplication, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QWidget, QLabel, QMainWindow
from client.client import sio, User, reg_callback
from PySide6.QtCore import QObject, QThread, Signal

username = None
user = User(None)
target_user = None
# Create a class for handling Socket.IO client operations
class SocketIOClient(QObject):
    message_received = Signal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        def on_message(data):
            print("pingi")
            self.message_received.emit(data)

        reg_callback(user, on_message)
        sio.wait()

# Create a worker thread to run the Socket.IO client
class Worker(QThread):
    def __init__(self):
        super().__init__()

    def run(self):
        self.client = SocketIOClient()
        self.client.message_received.connect(self.on_message_received)
        self.client.run()

    def on_message_received(self, message):
        print("Received message:", message)  # Do something with the received message, like updating the UI
        if target_user != None:
            mw.update_chat(user.messages[target_user])




# def send_message():
#     message = input_field.text()
#     if message:
#         chat_history.append(f'<font color="red">{message}</font>') 
#         input_field.clear()

# Create the Qt Application
app = QApplication(sys.argv)

class LoginScreen(QWidget):
    def __init__(self, parent=None):
        super(LoginScreen, self).__init__(parent)
        self.setWindowTitle("Login")
        self.username_label = QLabel("Username:")
        self.password_label = QLabel("Password:")
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_edit)
        layout.addWidget(self.login_button)
        self.setLayout(layout)

    def handle_login(self):
        global username
        # Check username and password, just a simple check for demo
        # if self.username_edit.text() == "user" and self.password_edit.text() == "password":
        #     self.parent().switch_to_chat_screen()
        # else:
        #     print("Invalid username or password")
        global user
        username = self.username_edit.text()
        user.username = username
        if(user.register_user()):
            
            self.parent().switch_to_select_screen()
        

class SelectScreen(QWidget):
    def __init__(self, parent=None):
        super(SelectScreen, self).__init__(parent)
        self.setWindowTitle("Select")

        # Create main layout
        self.main_layout = QVBoxLayout()
        self.main_layout.addWidget(QLabel("<h2>Connect to:</h2>"))

        # Refresh button
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        self.main_layout.addWidget(self.refresh_button)

        # User buttons layout
        self.user_layout = QVBoxLayout()
        self.main_layout.addLayout(self.user_layout)

        # Populate initial user list
        self.refresh()

        self.setLayout(self.main_layout)

    def refresh(self):
        # Clear previous user buttons
        for i in reversed(range(self.user_layout.count())):
            widget = self.user_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        # Retrieve users
        users = sio.call('request_users')
        print(users)
        # Add buttons for each user
        for u in users:
            if u != username:
                button = QPushButton(u)
                button.clicked.connect(lambda _, name=u: self.user_clicked(name))
                self.user_layout.addWidget(button)

    def user_clicked(self, name):
        global target_user
        target_user = name
        print(target_user)
        if not user.is_connected(target_user):
            user.request_user_prekey_bundle(target_user)
            user.perform_x3dh(target_user)
            print("connected")
        self.parent().switch_to_chat_screen()


        
class ChatScreen(QWidget):
    def __init__(self, parent=None):
        super(ChatScreen, self).__init__(parent)
        self.setWindowTitle("Chat")

        # Create main layout
        xlayout = QVBoxLayout()

        # Create chat layout
        chat_layout = QHBoxLayout()

        # Add back button - assuming you want a back button to return to the login screen
        back_button = QPushButton("Back")
        back_button.clicked.connect(self.back_message)
        toolbar_layout = QHBoxLayout()
        xlayout.addLayout(toolbar_layout)
        toolbar_layout.addWidget(back_button)

        # Add text area for chat history
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        xlayout.addWidget(self.chat_history)

        # Add input field and send button for new message
        self.input_field = QLineEdit()
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_message)
        chat_layout.addWidget(self.input_field)
        chat_layout.addWidget(send_button)
        xlayout.addLayout(chat_layout)

        self.setLayout(xlayout)
        
        self.update_messages(user.messages[target_user])
    def send_message(self):
        message = self.input_field.text()

        if message:
            self.input_field.clear()
            print("sending")
            user.send_message(target_user, message)
            self.update_messages(user.messages[target_user])

    def update_messages(self, messages):
        self.chat_history.clear()
        for sender, msg in messages:
            # Set color based on sender
            color = "green" if sender == username else "red"
            # Append message with color
            self.append_colored_text(sender, msg, color)

    def back_message(self):
        self.parent().switch_to_select_screen()
    def append_colored_text(self, sender, msg, color):    
        self.chat_history.append(f"<font color='{color}'> <strong>{sender}:</strong> {msg}</font><br>")


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.login_screen = LoginScreen(self)
        
        
        self.setCentralWidget(self.login_screen)

    def switch_to_chat_screen(self):
        self.chat_screen = ChatScreen(self)
        self.setCentralWidget(self.chat_screen)
    def switch_to_select_screen(self):
        self.select_screen = SelectScreen(self)
        self.setCentralWidget(self.select_screen)
    def update_chat(self, messages):
        self.chat_screen.update_messages(messages)
# Create main window

mw = MainWindow()
mw.show()


worker_thread = Worker()
worker_thread.start()


# Run the main Qt loop
sys.exit(app.exec())
