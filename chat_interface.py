import tkinter as tk

class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Interface : Alice")

        self.message_frame = tk.Frame(self.root)
        self.message_frame.pack(pady=10)

        self.chat_receiver = tk.Label(self.message_frame, text="Bob", font=("Helvetica", 15))
        self.chat_receiver.grid(row=0, column=0, sticky="w")

        self.message_label = tk.Label(self.message_frame, text="Messages:")
        self.message_label.grid(row=1, column=0, sticky="w")

        self.message_text = tk.Text(self.message_frame, width=50, height=20)
        self.message_text.grid(row=2, column=0)

        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(pady=10)

        self.input_label = tk.Label(self.input_frame, text="Enter Message:")
        self.input_label.grid(row=0, column=0, sticky="w")

        self.input_entry = tk.Entry(self.input_frame, width=50)
        self.input_entry.grid(row=1, column=0)

        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1)

    def send_message(self):
        message = self.input_entry.get()
        # Call the function to send the message here
        # For now, we'll just print the message
        print("Sending message:", message)
        self.input_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()