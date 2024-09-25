import os
import json
import hashlib
import atexit
import stat
import re
from tkinter import messagebox, Toplevel, Label, Button, simpledialog
from hasher import (
    hash_password,
    check_password,
    generate_encryption_key,
    encrypt_data,
    decrypt_data,
    verify_data_integrity,
    generate_salt,
)
import tkinter as tk


class FunctionalHandler:
    """
    Handles the core functionality of the password manager application.
    """

    def __init__(self, ui_handler):
        """
        Initializes the FunctionalHandler with a reference to the UIHandler.

        Args:
            ui_handler (UIHandler): The UIHandler instance to interact with the user interface.
        """
        self.ui_handler = ui_handler
        self.master_password = None
        self.user_vault = {}
        self.incorrect_attempts = 0
        self.is_running = True
        self.ensure_file_permissions()
        self.ensure_directory_permissions()
        atexit.register(self.safe_exit)

    def ensure_file_permissions(self):
        """
        Ensures that the necessary files have the correct permissions.
        """
        files = ["user_vault.json.enc", "user_vault.json.salt"]
        for file in files:
            if os.path.exists(file):
                current_permissions = stat.S_IMODE(os.lstat(file).st_mode)
                if current_permissions != (stat.S_IRUSR | stat.S_IWUSR):
                    try:
                        os.chmod(file, stat.S_IRUSR | stat.S_IWUSR)
                    except Exception as e:
                        self.show_custom_error(
                            "Permission Error",
                            f"Failed to set permissions of {file}: {e}",
                        )

    def ensure_directory_permissions(self):
        """
        Ensures that the directory containing the user vault files has the correct permissions.
        """
        directory = os.path.dirname(os.path.abspath("user_vault.json.enc"))
        if os.path.exists(directory):
            current_permissions = stat.S_IMODE(os.lstat(directory).st_mode)
            if current_permissions != (stat.S_IRWXU):
                try:
                    os.chmod(directory, stat.S_IRWXU)
                except Exception as e:
                    self.show_custom_error(
                        "Permission Error",
                        f"Failed to set permissions of {directory}: {e}",
                    )

    def sign_up(self):
        """
        Handles the user sign-up process.
        """
        self.ui_handler.sign_up_button.config(state=tk.DISABLED)
        master_password, confirm_password = self.ui_handler.get_master_passwords()

        if master_password is None or confirm_password is None:
            self.ui_handler.sign_up_button.config(state=tk.NORMAL)
            return

        if not master_password or master_password != confirm_password:
            self.show_custom_error("Error", "Passwords do not match or are invalid.")
            self.ui_handler.sign_up_button.config(state=tk.NORMAL)
            return
        if not self.is_strong_password(master_password):
            self.show_custom_error(
                "Error", "Password does not meet the strength requirements."
            )
            self.ui_handler.sign_up_button.config(state=tk.NORMAL)
            return

        salt = generate_salt()
        key = generate_encryption_key(master_password, salt)
        self.user_vault = {"salt": salt.hex(), "passwords": {}, "hashes": {}}
        self.save_user_vault(key)
        self.ui_handler.update_status_bar("Sign up successful. Please sign in.")
        self.ui_handler.update_buttons()
        self.ui_handler.sign_up_button.grid_remove()
        self.ui_handler.sign_in_button.grid()

    def sign_in(self):
        """
        Handles the user sign-in process.
        """
        self.ui_handler.sign_in_button.config(state=tk.DISABLED)
        master_password = self.ui_handler.get_sign_in_password()

        if master_password is None:
            self.ui_handler.sign_in_button.config(state=tk.NORMAL)
            return

        try:
            with open("user_vault.json.enc", "rb") as f:
                encrypted_data = f.read()
            with open("user_vault.json.salt", "rb") as f:
                salt = f.read()
            key = generate_encryption_key(master_password, salt)
            user_data = json.loads(decrypt_data(encrypted_data, key))
            self.master_password = master_password
            self.user_vault = user_data
            self.load_passwords()
            self.update_ui_for_signed_in_user()
            self.ui_handler.update_status_bar("Sign in successful.")
            self.incorrect_attempts = 0
            return
        except FileNotFoundError:
            self.show_custom_error(
                "Error", "No user vault found. Please sign up first."
            )
            self.ui_handler.sign_in_button.config(state=tk.NORMAL)
            return
        except Exception:
            self.incorrect_attempts += 1
            if self.incorrect_attempts >= 3:
                messagebox.showerror(
                    "Error",
                    "Too many incorrect attempts. The program will now terminate.",
                )
                self.ui_handler.root.destroy()
            else:
                self.show_custom_error("Error", "Incorrect master password.")
            self.ui_handler.sign_in_button.config(state=tk.NORMAL)

    def update_ui_for_signed_in_user(self):
        """
        Updates the UI to reflect that the user is signed in.
        """
        self.ui_handler.sign_out_button.config(state=tk.NORMAL)
        self.ui_handler.save_password_button.config(state=tk.NORMAL)
        self.ui_handler.save_password_button.grid()
        self.ui_handler.sign_in_button.config(state=tk.DISABLED)
        self.ui_handler.vault_label_frame.pack(fill=tk.X, padx=20, pady=(0, 10))
        self.ui_handler.display_vault()
        self.ui_handler.description_label.grid_remove()

    def sign_out(self):
        """
        Handles the user sign-out process.
        """
        self.save_user_vault(self.get_encryption_key())
        self.master_password = None
        self.user_vault = {}
        self.ui_handler.sign_out_button.config(state=tk.DISABLED)
        self.ui_handler.save_password_button.config(state=tk.DISABLED)
        self.ui_handler.save_password_button.grid_remove()
        self.ui_handler.sign_in_button.config(state=tk.NORMAL)
        self.ui_handler.vault_label_frame.pack_forget()
        self.ui_handler.close_vault()
        self.ui_handler.update_status_bar("Signed out.")
        self.ui_handler.update_buttons()
        self.ui_handler.description_label.grid()

    def save_password(self):
        """
        Handles the process of saving a new password.
        """
        self.ui_handler.save_password_button.config(state=tk.DISABLED)
        password_input, password_id = self.ui_handler.get_save_password_input()

        if password_input is None or password_id is None:
            self.ui_handler.save_password_button.config(state=tk.NORMAL)
            return

        if password_id in self.user_vault["passwords"]:
            action = self.handle_duplicate_password_id(password_id)
            if action == "overwrite":
                self.overwrite_password(password_id, password_input)
            elif action == "rename":
                self.save_password()
            elif action == "cancel":
                self.ui_handler.save_password_button.config(state=tk.NORMAL)
            return

        salt = bytes.fromhex(self.user_vault["salt"])
        key = generate_encryption_key(self.master_password, salt)
        encrypted_password = encrypt_data(password_input.encode(), key)
        self.user_vault["passwords"][password_id] = encrypted_password.decode()
        self.user_vault["hashes"][password_id] = hashlib.sha256(
            encrypted_password
        ).hexdigest()
        self.save_user_vault(key)
        messagebox.showinfo("Success", "Password saved.")
        self.ui_handler.display_vault()
        self.ui_handler.save_password_button.config(state=tk.NORMAL)

    def handle_duplicate_password_id(self, password_id):
        """
        Handles the scenario where a password ID already exists.

        Args:
            password_id (str): The password ID that already exists.

        Returns:
            str: The action to take ("overwrite", "rename", or "cancel").
        """
        response = self.ui_handler.show_duplicate_password_id_dialog(password_id)
        return response

    def overwrite_password(self, password_id, password_input):
        """
        Overwrites an existing password with a new one.

        Args:
            password_id (str): The ID of the password to overwrite.
            password_input (str): The new password to save.
        """
        salt = bytes.fromhex(self.user_vault["salt"])
        key = generate_encryption_key(self.master_password, salt)
        encrypted_password = encrypt_data(password_input.encode(), key)
        self.user_vault["passwords"][password_id] = encrypted_password.decode()
        self.user_vault["hashes"][password_id] = hashlib.sha256(
            encrypted_password
        ).hexdigest()
        self.save_user_vault(key)
        messagebox.showinfo("Success", "Password overwritten.")
        self.ui_handler.display_vault()
        self.ui_handler.save_password_button.config(state=tk.NORMAL)

    def view_password_from_list(self):
        """
        Handles the viewing of a password from the vault list.
        """
        selected_index = self.ui_handler.vault_listbox.curselection()
        if selected_index:
            password_id = self.ui_handler.vault_listbox.get(selected_index)
            encrypted_password = self.user_vault["passwords"][password_id].encode()
            self.view_password(password_id, encrypted_password)

    def view_hash_from_list(self):
        """
        Handles the viewing of a password hash from the vault list.
        """
        selected_index = self.ui_handler.vault_listbox.curselection()
        if selected_index:
            password_id = self.ui_handler.vault_listbox.get(selected_index)
            hash_value = self.user_vault["hashes"][password_id]
            self.ui_handler.view_hash(password_id, hash_value)

    def delete_password_from_list(self):
        """
        Handles the deletion of a password from the vault list.
        """
        selected_index = self.ui_handler.vault_listbox.curselection()
        if selected_index:
            password_id = self.ui_handler.vault_listbox.get(selected_index)
            confirm = messagebox.askyesno(
                "Confirm Delete", f"Are you sure you want to delete '{password_id}'?"
            )
            if confirm:
                del self.user_vault["passwords"][password_id]
                del self.user_vault["hashes"][password_id]
                key = self.get_encryption_key()
                self.save_user_vault(key)
                messagebox.showinfo("Success", f"Password '{password_id}' deleted.")
                self.ui_handler.display_vault()

    def view_password(self, password_id, encrypted_password):
        """
        Decrypts and displays a password.

        Args:
            password_id (str): The ID of the password to view.
            encrypted_password (bytes): The encrypted password.
        """
        salt = bytes.fromhex(self.user_vault["salt"])
        key = generate_encryption_key(self.master_password, salt)
        try:
            expected_hash = self.user_vault["hashes"][password_id]
            verify_data_integrity(encrypted_password, expected_hash)
            decrypted_password = decrypt_data(encrypted_password, key)
        except ValueError as e:
            self.show_custom_error("Error", str(e))
            return

        self.ui_handler.view_password(password_id, decrypted_password)

    def load_passwords(self):
        """
        Loads and verifies the integrity of all passwords in the vault.
        """
        salt = bytes.fromhex(self.user_vault["salt"])
        key = generate_encryption_key(self.master_password, salt)
        for password_id, encrypted_password in self.user_vault["passwords"].items():
            try:
                expected_hash = self.user_vault["hashes"][password_id]
                verify_data_integrity(encrypted_password.encode(), expected_hash)
                decrypt_data(encrypted_password.encode(), key)
            except ValueError as e:
                self.show_custom_error("Error", str(e))
                continue

    def is_strong_password(self, password):
        """
        Checks if a password meets the strength requirements.

        Args:
            password (str): The password to check.

        Returns:
            bool: True if the password is strong, False otherwise.
        """
        # Regex pattern to match all possible passwords meeting the criteria
        regex = re.compile(
            r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[ \t\n\r\f\v!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?])[A-Za-z\d \t\n\r\f\v!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}$"
        )
        return regex.match(password) is not None

    def save_user_vault(self, key):
        """
        Saves the user vault to disk.

        Args:
            key (bytes): The encryption key to use for saving the vault.
        """
        if self.user_vault and "salt" in self.user_vault:
            json_data = json.dumps(self.user_vault).encode()
            encrypted_data = encrypt_data(json_data, key)
            with open("user_vault.json.enc", "wb") as f:
                f.write(encrypted_data)
            with open("user_vault.json.salt", "wb") as f:
                f.write(bytes.fromhex(self.user_vault["salt"]))

            os.chmod("user_vault.json.enc", stat.S_IRUSR | stat.S_IWUSR)
            os.chmod("user_vault.json.salt", stat.S_IRUSR | stat.S_IWUSR)

            # Debugging statement to check if files are created
            print("Files created:")
            print(
                f"user_vault.json.enc exists: {os.path.exists('user_vault.json.enc')}"
            )
            print(
                f"user_vault.json.salt exists: {os.path.exists('user_vault.json.salt')}"
            )

    def get_encryption_key(self):
        """
        Generates the encryption key from the master password and salt.

        Returns:
            bytes: The encryption key.
        """
        if (
            self.user_vault
            and "salt" in self.user_vault
            and self.master_password is not None
        ):
            salt = bytes.fromhex(self.user_vault["salt"])
            return generate_encryption_key(self.master_password, salt)
        return None

    def safe_exit(self):
        """
        Ensures the user vault is saved before the application exits.
        """
        if (
            self.user_vault
            and "salt" in self.user_vault
            and self.master_password is not None
        ):
            self.save_user_vault(self.get_encryption_key())
        if self.is_running:
            self.is_running = False
            try:
                self.ui_handler.root.destroy()
            except tk.TclError:
                pass

    def show_custom_error(self, title, message):
        """
        Displays a custom error message.

        Args:
            title (str): The title of the error message.
            message (str): The error message to display.
        """
        self.ui_handler.show_custom_error(title, message)
