import tkinter as tk
from tkinter import messagebox, Toplevel, Label, Button, Menu, simpledialog
import os
import secrets


class PasswordEntry(tk.Frame):
    """
    A custom Tkinter frame for entering passwords with an option to toggle visibility.
    """

    def __init__(self, master, show_toggle=True, *args, **kwargs):
        """
        Initializes the PasswordEntry frame.

        Args:
            master (tk.Widget): The parent widget.
            show_toggle (bool): Whether to show the toggle button for password visibility.
        """
        super().__init__(master, *args, **kwargs)
        self.show_toggle = show_toggle
        self.password_var = tk.StringVar()
        self.entry = tk.Entry(self, textvariable=self.password_var, show="*")
        self.entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        if self.show_toggle:
            self.toggle_var = tk.BooleanVar()
            self.toggle_button = tk.Checkbutton(
                self,
                text="Show",
                variable=self.toggle_var,
                command=self.toggle_password_visibility,
            )
            self.toggle_button.pack(side=tk.RIGHT)

    def toggle_password_visibility(self):
        """
        Toggles the visibility of the password in the entry widget.
        """
        self.entry.config(show="" if self.toggle_var.get() else "*")

    def get(self):
        """
        Gets the current value of the password entry.

        Returns:
            str: The current password.
        """
        return self.password_var.get()

    def set(self, value):
        """
        Sets the value of the password entry.

        Args:
            value (str): The value to set.
        """
        self.password_var.set(value)


class UIHandler:
    """
    Handles the user interface for the password manager application.
    """

    def __init__(self, root, functional_handler):
        """
        Initializes the UIHandler with a reference to the root window and the FunctionalHandler.

        Args:
            root (tk.Tk): The root window of the application.
            functional_handler (FunctionalHandler): The FunctionalHandler instance to interact with the core functionality.
        """
        self.root = root
        self.functional_handler = functional_handler
        self.create_widgets()
        self.update_buttons()

    def create_widgets(self):
        """
        Creates and configures the widgets for the main application window.
        """
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.sign_up_button = tk.Button(
            main_frame, text="Sign Up", command=self.functional_handler.sign_up
        )
        self.sign_up_button.grid(row=0, column=0, padx=5, pady=(5, 15), sticky="ew")

        self.sign_in_button = tk.Button(
            main_frame, text="Sign In", command=self.functional_handler.sign_in
        )
        self.sign_in_button.grid(row=0, column=1, padx=5, pady=(5, 15), sticky="ew")

        self.sign_out_button = tk.Button(
            main_frame,
            text="Sign Out",
            command=self.functional_handler.sign_out,
            state=tk.DISABLED,
        )
        self.sign_out_button.grid(row=0, column=2, padx=5, pady=(5, 15), sticky="ew")

        self.save_password_button = tk.Button(
            main_frame,
            text="Save Password",
            command=self.functional_handler.save_password,
            state=tk.DISABLED,
        )
        self.save_password_button.grid(
            row=0, column=3, padx=5, pady=(5, 15), sticky="ew"
        )
        self.save_password_button.grid_remove()

        # Add label frame for "Password Vault"
        self.vault_label_frame = tk.Frame(self.root)
        self.vault_label_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        self.vault_label_frame.pack_forget()  # Hide the label frame initially

        self.vault_label = tk.Label(
            self.vault_label_frame,
            text="Password Vault",
            font=("Arial", 12, "underline"),
        )
        self.vault_label.pack()

        self.vault_frame = tk.Frame(self.root)
        self.vault_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        self.vault_frame.pack_forget()

        self.vault_listbox = tk.Listbox(self.vault_frame, width=50, height=10)
        self.vault_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vault_listbox.bind("<Button-3>", self.show_context_menu)

        self.vault_scrollbar = tk.Scrollbar(
            self.vault_frame, orient=tk.VERTICAL, command=self.vault_listbox.yview
        )
        self.vault_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.vault_listbox.config(yscrollcommand=self.vault_scrollbar.set)

        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(
            label="View Password",
            command=self.functional_handler.view_password_from_list,
        )
        self.context_menu.add_command(
            label="View Hash", command=self.functional_handler.view_hash_from_list
        )
        self.context_menu.add_command(
            label="Delete", command=self.functional_handler.delete_password_from_list
        )
        self.context_menu.add_command(label="Cancel", command=self.context_menu.unpost)

        # Add watermark
        watermark_frame = tk.Frame(self.root)
        watermark_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=10)

        watermark_label = tk.Label(
            watermark_frame, text="Developed by ", font=("Arial", 8)
        )
        watermark_label.pack(side=tk.LEFT)

        github_link = tk.Label(
            watermark_frame,
            text="https://github.com/FreakNorris",
            font=("Arial", 8),
            fg="blue",
        )
        github_link.pack(side=tk.LEFT)

        # Status bar
        self.status_bar = tk.Label(
            self.root, text="", bd=1, relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure grid weights for responsive design
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_columnconfigure(2, weight=1)
        main_frame.grid_columnconfigure(3, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        # Add description label to the initial screen
        self.description_label = tk.Label(
            main_frame,
            text="Security Features and Methodology:\n\n"
            "- bcrypt: Secure password hashing.\n"
            "- Fernet: Symmetric encryption with integrity checks.\n"
            "- PBKDF2HMAC with SHA256: Key derivation with 100,000 iterations.\n"
            "- Unique salts.\n"
            "- Key derived from master password and salt.\n"
            "- SHA256 for data integrity checks.",
            wraplength=450,
            justify=tk.CENTER,
        )
        self.description_label.grid(
            row=1, column=0, columnspan=4, padx=5, pady=(15, 5), sticky="ew"
        )

    def update_buttons(self):
        """
        Updates the state of the buttons based on the presence of the user vault file.
        """
        if os.path.exists("user_vault.json.enc"):
            self.sign_up_button.grid_remove()
            self.sign_in_button.grid()
        else:
            self.sign_up_button.grid()
            self.sign_in_button.grid_remove()

    def show_context_menu(self, event):
        """
        Displays the context menu for the vault listbox.

        Args:
            event (tk.Event): The event that triggered the context menu.
        """
        self.vault_listbox.selection_set(self.vault_listbox.nearest(event.y))
        self.context_menu.post(event.x_root, event.y_root)

    def update_status_bar(self, message):
        """
        Updates the status bar with the given message.

        Args:
            message (str): The message to display in the status bar.
        """
        self.status_bar.config(text=message)

    def get_master_passwords(self):
        """
        Opens a dialog to get the master password and its confirmation.

        Returns:
            tuple: A tuple containing the master password and the confirmation password.
        """
        dialog = Toplevel(self.root)
        dialog.title("Create Master Password")
        dialog.geometry("500x300")
        dialog.minsize(300, 300)

        hint_label = tk.Label(
            dialog,
            text="Password must be at least 8 characters long and contain:\n- At least one uppercase letter\n- At least one lowercase letter\n- At least one digit\n- At least one special character (@$!%*?&)",
            justify=tk.LEFT,
        )
        hint_label.pack(fill=tk.X, padx=20, pady=5)

        master_password_entry = PasswordEntry(dialog, show_toggle=True)
        master_password_entry.pack(fill=tk.X, padx=20, pady=5)

        confirm_password_entry = PasswordEntry(dialog, show_toggle=True)
        confirm_password_entry.pack(fill=tk.X, padx=20, pady=5)

        def on_ok(event=None):
            dialog.master_password = master_password_entry.get()
            dialog.confirm_password = confirm_password_entry.get()
            dialog.destroy()

        def on_cancel(event=None):
            dialog.master_password = None
            dialog.confirm_password = None
            dialog.destroy()

        ok_button = Button(dialog, text="OK", command=on_ok)
        ok_button.pack(side=tk.LEFT, padx=20, pady=10)
        dialog.bind("<Return>", on_ok)

        cancel_button = Button(dialog, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.RIGHT, padx=20, pady=10)
        dialog.bind("<Escape>", on_cancel)

        dialog.master_password = None
        dialog.confirm_password = None
        dialog.wait_window()

        return dialog.master_password, dialog.confirm_password

    def get_sign_in_password(self):
        """
        Opens a dialog to get the master password for signing in.

        Returns:
            str: The master password.
        """
        dialog = Toplevel(self.root)
        dialog.title("Sign In")
        dialog.geometry("500x200")
        dialog.minsize(300, 200)

        reminder_label = tk.Label(
            dialog,
            text="Remember your password! It's crucial for accessing your vault.",
            wraplength=400,
            justify=tk.CENTER,
        )
        reminder_label.pack(fill=tk.X, padx=20, pady=10)

        master_password_entry = PasswordEntry(dialog, show_toggle=True)
        master_password_entry.pack(fill=tk.X, padx=20, pady=5)

        def on_ok(event=None):
            dialog.master_password = master_password_entry.get()
            dialog.destroy()

        def on_cancel(event=None):
            dialog.master_password = None
            dialog.destroy()

        ok_button = Button(dialog, text="OK", command=on_ok)
        ok_button.pack(side=tk.LEFT, padx=20, pady=10)
        dialog.bind("<Return>", on_ok)

        cancel_button = Button(dialog, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.RIGHT, padx=20, pady=10)
        dialog.bind("<Escape>", on_cancel)

        dialog.master_password = None
        dialog.wait_window()

        return dialog.master_password

    def get_save_password_input(self):
        """
        Opens a dialog to get the password and its ID for saving.

        Returns:
            tuple: A tuple containing the password and its ID.
        """
        dialog = Toplevel(self.root)
        dialog.title("Save Password")
        dialog.geometry("580x250")
        dialog.minsize(300, 250)

        tk.Label(dialog, text="Password:").pack(fill=tk.X, padx=20, pady=5)
        password_entry = PasswordEntry(dialog, show_toggle=True)
        password_entry.pack(fill=tk.X, padx=20, pady=5)

        tk.Label(dialog, text="Password ID:").pack(fill=tk.X, padx=20, pady=5)
        password_id_entry = tk.Entry(dialog)
        password_id_entry.pack(fill=tk.X, padx=20, pady=5)

        def on_ok(event=None):
            password_input = password_entry.get()
            password_id = password_id_entry.get()
            if len(password_input) >= 8 and len(password_id) > 0:
                dialog.password_input = password_input
                dialog.password_id = password_id
                dialog.destroy()
            else:
                messagebox.showerror(
                    "Error",
                    "Password must be at least 8 characters and Password ID must not be empty.",
                )

        def on_cancel(event=None):
            dialog.password_input = None
            dialog.password_id = None
            dialog.destroy()

        ok_button = Button(dialog, text="OK", command=on_ok)
        ok_button.pack(side=tk.LEFT, padx=20, pady=10)
        dialog.bind("<Return>", on_ok)

        cancel_button = Button(dialog, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.RIGHT, padx=20, pady=10)
        dialog.bind("<Escape>", on_cancel)

        dialog.password_input = None
        dialog.password_id = None
        dialog.wait_window()

        return dialog.password_input, dialog.password_id

    def display_vault(self):
        """
        Displays the list of passwords in the vault.
        """
        self.vault_listbox.delete(0, tk.END)
        for password_id in self.functional_handler.user_vault["passwords"]:
            self.vault_listbox.insert(tk.END, password_id)
        self.vault_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

    def close_vault(self):
        """
        Hides the vault frame.
        """
        self.vault_frame.pack_forget()

    def view_password(self, password_id, decrypted_password):
        """
        Opens a window to view the decrypted password.

        Args:
            password_id (str): The ID of the password.
            decrypted_password (str): The decrypted password.
        """
        view_window = tk.Toplevel(self.root)
        view_window.title(f"View '{password_id}'")
        view_window.minsize(300, 200)
        view_window.geometry("580x200")

        tk.Label(view_window, text="Password ID:").pack(padx=5, pady=5)
        password_id_text = tk.Text(view_window, width=40, height=1)
        password_id_text.pack(padx=5, pady=5)
        password_id_text.insert(tk.END, password_id)
        password_id_text.config(state=tk.DISABLED)

        tk.Label(view_window, text="Password:").pack(padx=5, pady=5)
        password_text = tk.Text(view_window, width=40, height=1)
        password_text.pack(padx=5, pady=5)
        password_text.insert(tk.END, decrypted_password)
        password_text.config(state=tk.DISABLED)

        view_window.bind("<Escape>", lambda e: view_window.destroy())

    def view_hash(self, password_id, hash_value):
        """
        Opens a window to view the hash of the password.

        Args:
            password_id (str): The ID of the password.
            hash_value (str): The hash value of the password.
        """
        view_window = tk.Toplevel(self.root)
        view_window.title(f"View Hash for '{password_id}'")
        view_window.geometry("580x300")
        view_window.minsize(300, 300)

        tk.Label(view_window, text="Password ID:").pack(padx=5, pady=5)
        password_id_text = tk.Text(view_window, width=40, height=1)
        password_id_text.pack(padx=5, pady=5)
        password_id_text.insert(tk.END, password_id)
        password_id_text.config(state=tk.DISABLED)

        tk.Label(view_window, text="Hash:").pack(padx=5, pady=5)
        hash_text = tk.Text(view_window, width=60, height=5)
        hash_text.pack(padx=5, pady=5)
        hash_text.insert(tk.END, hash_value)
        hash_text.config(state=tk.DISABLED)

        view_window.bind("<Escape>", lambda e: view_window.destroy())

    def show_custom_error(self, title, message):
        """
        Displays a custom error message in a popup window.

        Args:
            title (str): The title of the error message.
            message (str): The error message to display.
        """
        popup = Toplevel(self.root)
        popup.title(title)
        popup.minsize(300, 150)
        label = Label(popup, text=message)
        label.pack(padx=20, pady=20)
        button = Button(popup, text="OK", command=popup.destroy)
        button.pack(pady=10)

        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        width = popup.winfo_width()
        height = popup.winfo_height()
        x = (
            parent_x + secrets.randbelow(201) - 100
        )  # Use secrets for secure random numbers
        y = (
            parent_y + secrets.randbelow(201) - 100
        )  # Use secrets for secure random numbers
        popup.geometry(f"+{x}+{y}")

        popup.bind("<Return>", lambda e: "break")
        popup.bind("<space>", lambda e: "break")
        popup.bind("<Tab>", lambda e: "break")

    def show_duplicate_password_id_dialog(self, password_id):
        """
        Displays a dialog to handle duplicate password IDs.

        Args:
            password_id (str): The ID of the password that already exists.

        Returns:
            str: The action to take ("overwrite", "rename", or "cancel").
        """
        dialog = Toplevel(self.root)
        dialog.title("Duplicate Password ID")
        dialog.geometry("400x150")
        dialog.minsize(300, 150)

        tk.Label(
            dialog,
            text=f"The password ID '{password_id}' already exists. What would you like to do?",
            wraplength=350,
            justify=tk.CENTER,
        ).pack(padx=20, pady=20)

        response = None

        def on_overwrite():
            nonlocal response
            response = "overwrite"
            dialog.destroy()

        def on_rename():
            nonlocal response
            response = "rename"
            dialog.destroy()

        def on_cancel():
            nonlocal response
            response = "cancel"
            dialog.destroy()

        overwrite_button = Button(dialog, text="Overwrite", command=on_overwrite)
        overwrite_button.pack(side=tk.LEFT, padx=20, pady=10)

        rename_button = Button(dialog, text="Rename", command=on_rename)
        rename_button.pack(side=tk.LEFT, padx=20, pady=10)

        cancel_button = Button(dialog, text="Cancel", command=on_cancel)
        cancel_button.pack(side=tk.LEFT, padx=20, pady=10)

        dialog.wait_window()
        return response
