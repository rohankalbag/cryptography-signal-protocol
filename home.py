import tkinter as tk

class HomeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Let's Chat")

        # Create label for the app name
        self.app_name_label = tk.Label(self.root, text="Let's Chat", font=("Arial", 24, "bold"))
        self.app_name_label.pack(pady=10)

        # Display welcome message for a specific user
        self.welcome_label = tk.Label(self.root, text="Welcome Bob", font=("Arial", 14))
        self.welcome_label.pack(pady=10)

        # Create dropdown for user selection
        self.user_selection_frame = tk.Frame(self.root)
        self.user_selection_frame.pack(pady=10)

        self.user_label = tk.Label(self.user_selection_frame, text="Select User:")
        self.user_label.grid(row=0, column=0)

        self.users = ['Alice', 'Bob', 'Charlie']  # Example users
        self.selected_user = tk.StringVar()
        self.selected_user.set(self.users[0])  # Default selection

        self.user_dropdown = tk.OptionMenu(self.user_selection_frame, self.selected_user, *self.users)
        self.user_dropdown.grid(row=0, column=1)

        # Create button for initiating chat
        self.chat_button = tk.Button(self.root, text="Start Chat", command=self.start_chat)
        self.chat_button.pack(pady=10)

    def start_chat(self):
        selected_user = self.selected_user.get()
        # Start chat with selected user, you can add your logic here

if __name__ == "__main__":
    root = tk.Tk()
    app = HomeApp(root)
    root.mainloop()
