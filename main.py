import tkinter as tk
from tkinter import messagebox, simpledialog, font, ttk
from datetime import datetime
from cryptography.fernet import Fernet
import os
import json

# Utility functions for encryption and decryption
def generate_key():
    return Fernet.generate_key()

def load_key(username):
    with open(f"{username}_key.key", "rb") as key_file:
        return key_file.read()

def save_key(username, key):
    with open(f"{username}_key.key", "wb") as key_file:
        key_file.write(key)

def encrypt_data(key, data):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def decrypt_data(key, data):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

class Entry:
    def __init__(self, title, content, timestamp=None):
        self.title = title
        self.content = content
        self.timestamp = timestamp or datetime.now()

    def __str__(self):
        return f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {self.title}"

    def to_dict(self):
        return {
            'title': self.title,
            'content': self.content,
            'timestamp': self.timestamp.isoformat()
        }

    @staticmethod
    def from_dict(entry_dict):
        return Entry(
            title=entry_dict['title'],
            content=entry_dict['content'],
            timestamp=datetime.fromisoformat(entry_dict['timestamp'])
        )

class Diary:
    def __init__(self, username):
        self.username = username
        self.entries = []
        self.load_entries()

    def add_entry(self, entry):
        self.entries.append(entry)
        self.save_entries()
        messagebox.showinfo("Success", "Entry added successfully!")

    def get_entries(self):
        return self.entries

    def delete_entry(self, index):
        if 0 <= index < len(self.entries):
            del self.entries[index]
            self.save_entries()
            messagebox.showinfo("Success", "Entry deleted successfully!")
        else:
            messagebox.showerror("Error", "Invalid entry index")

    def edit_entry(self, index, new_title, new_content):
        if 0 <= index < len(self.entries):
            self.entries[index].title = new_title
            self.entries[index].content = new_content
            self.entries[index].timestamp = datetime.now()
            self.save_entries()
            messagebox.showinfo("Success", "Entry edited successfully!")
        else:
            messagebox.showerror("Error", "Invalid entry index")

    def save_entries(self):
        key = load_key(self.username)
        entries_data = json.dumps([entry.to_dict() for entry in self.entries])
        encrypted_data = encrypt_data(key, entries_data)
        with open(f"{self.username}_entries.enc", "wb") as file:
            file.write(encrypted_data)

    def load_entries(self):
        if os.path.exists(f"{self.username}_entries.enc"):
            key = load_key(self.username)
            with open(f"{self.username}_entries.enc", "rb") as file:
                encrypted_data = file.read()
            entries_data = decrypt_data(key, encrypted_data)
            entries_dicts = json.loads(entries_data)
            self.entries = [Entry.from_dict(entry) for entry in entries_dicts]

class User:
    def __init__(self, username):
        self.username = username
        self.diary = Diary(username)

    def add_entry(self, title, content):
        entry = Entry(title, content)
        self.diary.add_entry(entry)

    def view_entries(self):
        return self.diary.get_entries()

    def delete_entry(self, index):
        self.diary.delete_entry(index)

    def edit_entry(self, index, new_title, new_content):
        self.diary.edit_entry(index, new_title, new_content)

class DiaryApp:
    def __init__(self, root):
        self.user = None
        self.root = root
        self.root.title("Digital Diary")
        self.root.geometry("700x600")

        # Fonts and Styles
        self.title_font = font.Font(family="Helvetica", size=14, weight="bold")
        self.content_font = font.Font(family="Helvetica", size=12)
        self.button_font = font.Font(family="Helvetica", size=12)
        self.entry_font = font.Font(family="Helvetica", size=10)

        style = ttk.Style()
        style.configure('TButton', font=self.button_font)

        # Main frame
        self.main_frame = tk.Frame(root, bg="#f0f0f0")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Frame for login/register
        self.frame_login = tk.Frame(self.main_frame, bg="#f0f0f0")
        self.frame_login.pack(pady=10, padx=10, fill=tk.X)

        self.label_username = tk.Label(self.frame_login, text="Username", font=self.title_font, bg="#f0f0f0")
        self.label_username.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_username = tk.Entry(self.frame_login, width=30, font=self.entry_font)
        self.entry_username.grid(row=0, column=1, padx=5, pady=5)

        self.label_password = tk.Label(self.frame_login, text="Password", font=self.title_font, bg="#f0f0f0")
        self.label_password.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_password = tk.Entry(self.frame_login, width=30, font=self.entry_font, show="*")
        self.entry_password.grid(row=1, column=1, padx=5, pady=5)

        self.button_login = ttk.Button(self.frame_login, text="Login", command=self.login)
        self.button_login.grid(row=2, column=0, padx=5, pady=5)
        self.button_register = ttk.Button(self.frame_login, text="Register", command=self.register)
        self.button_register.grid(row=2, column=1, padx=5, pady=5)

        # Frame for adding entries
        self.frame_add = tk.Frame(self.main_frame, bg="#f0f0f0")
        self.frame_add.pack(pady=10, padx=10, fill=tk.X)

        self.label_title = tk.Label(self.frame_add, text="Title", font=self.title_font, bg="#f0f0f0")
        self.label_title.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_title = tk.Entry(self.frame_add, width=50, font=self.entry_font)
        self.entry_title.grid(row=0, column=1, padx=5, pady=5)

        self.label_content = tk.Label(self.frame_add, text="Content", font=self.title_font, bg="#f0f0f0")
        self.label_content.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.text_content = tk.Text(self.frame_add, width=50, height=10, font=self.entry_font)
        self.text_content.grid(row=1, column=1, padx=5, pady=5)

        self.button_add = ttk.Button(self.frame_add, text="Add Entry", command=self.add_entry)
        self.button_add.grid(row=2, columnspan=2, pady=10)

        # Frame for viewing entries
        self.frame_view = tk.Frame(self.main_frame, bg="#f0f0f0")
        self.frame_view.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.button_view = ttk.Button(self.frame_view, text="View Entries", command=self.view_entries)
        self.button_view.pack(pady=5)

        self.text_entries = tk.Text(self.frame_view, width=60, height=20, state=tk.DISABLED, font=self.content_font, wrap=tk.WORD)
        self.text_entries.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Frame for editing and deleting entries
        self.frame_manage = tk.Frame(self.main_frame, bg="#f0f0f0")
        self.frame_manage.pack(pady=10, padx=10, fill=tk.X)

        self.label_entry_index = tk.Label(self.frame_manage, text="Entry Index", font=self.title_font, bg="#f0f0f0")
        self.label_entry_index.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.entry_index = tk.Entry(self.frame_manage, width=10, font=self.entry_font)
        self.entry_index.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.button_edit = ttk.Button(self.frame_manage, text="Edit Entry", command=self.edit_entry)
        self.button_edit.grid(row=0, column=2, padx=5, pady=5)

        self.button_delete = ttk.Button(self.frame_manage, text="Delete Entry", command=self.delete_entry)
        self.button_delete.grid(row=0, column=3, padx=5, pady=5)

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if os.path.exists(f"{username}.json"):
            with open(f"{username}.json", "r") as file:
                user_data = json.load(file)
            if user_data["username"] == username and user_data["password"] == password:
                self.user = User(username)
                messagebox.showinfo("Success", "Logged in successfully!")
            else:
                messagebox.showerror("Error", "Invalid username or password")
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if os.path.exists(f"{username}.json"):
            messagebox.showerror("Error", "Username already exists")
        else:
            key = generate_key()
            save_key(username, key)
            user_data = {"username": username, "password": password}
            with open(f"{username}.json", "w") as file:
                json.dump(user_data, file)
            self.user = User(username)
            messagebox.showinfo("Success", "Registered successfully!")

    def add_entry(self):
        if self.user:
            title = self.entry_title.get()
            content = self.text_content.get("1.0", tk.END).strip()
            if title and content:
                self.user.add_entry(title, content)
                self.entry_title.delete(0, tk.END)
                self.text_content.delete("1.0", tk.END)
            else:
                messagebox.showerror("Error", "Title and content cannot be empty")
        else:
            messagebox.showerror("Error", "You must be logged in to add an entry")

    def view_entries(self):
        if self.user:
            entries = self.user.view_entries()
            self.text_entries.config(state=tk.NORMAL)
            self.text_entries.delete("1.0", tk.END)
            for i, entry in enumerate(entries):
                self.text_entries.insert(tk.END, f"{i}: {entry}\n")
            self.text_entries.config(state=tk.DISABLED)
        else:
            messagebox.showerror("Error", "You must be logged in to view entries")

    def delete_entry(self):
        if self.user:
            try:
                index = int(self.entry_index.get())
                self.user.delete_entry(index)
                self.view_entries()
                self.entry_index.delete(0, tk.END)
            except ValueError:
                messagebox.showerror("Error", "Invalid entry index")
        else:
            messagebox.showerror("Error", "You must be logged in to delete an entry")

    def edit_entry(self):
        if self.user:
            try:
                index = int(self.entry_index.get())
                new_title = simpledialog.askstring("Edit Entry", "Enter new title")
                new_content = simpledialog.askstring("Edit Entry", "Enter new content")
                if new_title and new_content:
                    self.user.edit_entry(index, new_title, new_content)
                    self.view_entries()
                    self.entry_index.delete(0, tk.END)
                else:
                    messagebox.showerror("Error", "Title and content cannot be empty")
            except ValueError:
                messagebox.showerror("Error", "Invalid entry index")
        else:
            messagebox.showerror("Error", "You must be logged in to edit an entry")

if __name__ == "__main__":
    root = tk.Tk()
    app = DiaryApp(root)
    root.mainloop()
