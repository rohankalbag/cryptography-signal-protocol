import sys
from PySide6.QtWidgets import QApplication, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, QWidget
from client.client import sio
from PySide6.QtCore import QObject, QThread, Signal

# Create a class for handling Socket.IO client operations
class SocketIOClient(QObject):
    message_received = Signal(str)

    def __init__(self):
        super().__init__()

    def run(self):
        @sio.on('pingi')
        def on_message(data):
            print("pingi")
            self.message_received.emit(data)

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

def send_message():
    message = input_field.text()
    if message:
        print("sending")
        sio.emit("pongi", "sankalp")

# def send_message():
#     message = input_field.text()
#     if message:
#         chat_history.append(f'<font color="red">{message}</font>') 
#         input_field.clear()

# Create the Qt Application
app = QApplication(sys.argv)

# Create main layout
layout = QVBoxLayout()

# Create chat layout
chat_layout = QHBoxLayout()

# Add back button
layout.addWidget(QPushButton("Back"))

# Add text area for chat history
chat_history = QTextEdit()
chat_history.setReadOnly(True)
layout.addWidget(chat_history)

# Add input field and send button for new message
input_field = QLineEdit()
send_button = QPushButton("Send")
send_button.clicked.connect(send_message)
chat_layout.addWidget(input_field)
chat_layout.addWidget(send_button)
layout.addLayout(chat_layout)

# Create main window
window = QWidget()
window.setLayout(layout)
window.show()

worker_thread = Worker()
worker_thread.start()


# Run the main Qt loop
sys.exit(app.exec())
