'''
    PYTHON SQL PASSWORD MANAGER
               CLI
             V-1.0.0
Author : KYRIAKOS ANTONIADIS
mail : kuriakosant2003@gmail.com    
github : https://github.com/kuriakosant
linkedin : https://www.linkedin.com/in/kyriakos-antoniadis-288444326/
'''

import os
import sqlite3
import getpass
import bcrypt
from cryptography.fernet import Fernet
import base64
import sys
from colorama import Fore, Back, Style, init

# Initialize Colorama
init(autoreset=True)

# Database file
DB_FILE = "password_manager.db"

class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = self.connect_db()
        self.create_tables()

    def connect_db(self):
        return sqlite3.connect(self.db_file)

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS master_info (id INTEGER PRIMARY KEY, master_password_hash TEXT, failed_attempts INTEGER, encryption_key BLOB)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, website TEXT UNIQUE, username TEXT, encrypted_password TEXT, name TEXT, email TEXT, custom_field TEXT)''')
        self.conn.commit()

    def execute_query(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor

    def fetch_one(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()

    def fetch_all(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def close(self):
        self.conn.close()

class PasswordManager:
    def __init__(self, db_manager):
        self.db_manager = db_manager

    def generate_key(self):
        return Fernet.generate_key()

    def encrypt_password(self, password, key):
        cipher_suite = Fernet(key)
        return cipher_suite.encrypt(password.encode())

    def decrypt_password(self, encrypted_password, key):
        cipher_suite = Fernet(key)
        return cipher_suite.decrypt(encrypted_password).decode()

    def hash_master_password(self, password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt)

    def check_master_password(self, input_password, stored_hash):
        return bcrypt.checkpw(input_password.encode(), stored_hash)

    def store_encryption_key(self, key, master_password_hash):
        cipher_suite = Fernet(base64.urlsafe_b64encode(master_password_hash[:32]))
        return cipher_suite.encrypt(key)

    def retrieve_encryption_key(self, encrypted_key, master_password_hash):
        cipher_suite = Fernet(base64.urlsafe_b64encode(master_password_hash[:32]))
        return cipher_suite.decrypt(encrypted_key)

    def add_password(self, website, username, password, key, name=None, email=None, custom_field=None):
        if self.db_manager.fetch_one("SELECT 1 FROM credentials WHERE website = ?", (website,)):
            print(Fore.RED + f"Website '{website}' already exists. Please use a different name.")
            return False
        encrypted_password = self.encrypt_password(password, key)
        self.db_manager.execute_query("INSERT INTO credentials (website, username, encrypted_password, name, email, custom_field) VALUES (?, ?, ?, ?, ?, ?)",
                                      (website, username, encrypted_password, name, email, custom_field))
        print(Fore.GREEN + "Password added successfully!")
        return True

    def view_websites(self):
        return self.db_manager.fetch_all("SELECT website FROM credentials")

    def view_password(self, website, key):
        result = self.db_manager.fetch_one("SELECT encrypted_password, name, email, custom_field FROM credentials WHERE website = ?", (website,))
        if result:
            encrypted_password, name, email, custom_field = result
            decrypted_password = self.decrypt_password(encrypted_password, key)
            return {
                "password": decrypted_password,
                "name": name,
                "email": email,
                "custom_field": custom_field
            }
        else:
            return None

    def delete_password(self, website, key, master_password):
        # Confirm the master password
        result = self.db_manager.fetch_one("SELECT master_password_hash FROM master_info")
        if result:
            stored_hash = result[0]
            if not self.check_master_password(master_password, stored_hash):
                print(Fore.RED + "Incorrect master password. Deletion aborted.")
                return False

        # Check if the website exists
        if not self.db_manager.fetch_one("SELECT 1 FROM credentials WHERE website = ?", (website,)):
            print(Fore.RED + f"Website '{website}' does not exist. Deletion aborted.")
            return False

        # Delete the password
        self.db_manager.execute_query("DELETE FROM credentials WHERE website = ?", (website,))
        print(Fore.GREEN + f"Password for '{website}' has been deleted.")
        return True

class CLI:
    def __init__(self):
        self.db_manager = DatabaseManager(DB_FILE)
        self.password_manager = PasswordManager(self.db_manager)
        self.key = None

    def login(self):
        result = self.db_manager.fetch_one("SELECT master_password_hash, encryption_key, failed_attempts FROM master_info")
        if result:
            stored_hash, encrypted_key, failed_attempts = result
            if failed_attempts >= 10:
                print(Fore.RED + "Too many failed attempts. Deleting all passwords...")
                self.db_manager.execute_query("DELETE FROM credentials")
                self.db_manager.execute_query("DELETE FROM master_info")  # Delete master password
                os.remove(DB_FILE)  # Remove the database file
                sys.exit(0)

            for attempt in range(10):
                master_password = getpass.getpass(Fore.YELLOW + "Enter Master Password: ")
                if self.password_manager.check_master_password(master_password, stored_hash):
                    self.db_manager.execute_query("UPDATE master_info SET failed_attempts = 0")
                    print(Fore.GREEN + "Login successful!")
                    self.key = self.password_manager.retrieve_encryption_key(encrypted_key, stored_hash)
                    return True
                else:
                    self.db_manager.execute_query("UPDATE master_info SET failed_attempts = failed_attempts + 1")
                    print(Fore.RED + f"Incorrect password. Attempt {attempt + 1}/10")

            # If the user fails 10 times, the following code will execute
            print(Fore.RED + "Too many failed attempts. Deleting all passwords...")
            self.db_manager.execute_query("DELETE FROM credentials")
            self.db_manager.execute_query("DELETE FROM master_info")  # Delete master password
            os.remove(DB_FILE)  # Remove the database file
            sys.exit(0)
        else:
            print(Fore.YELLOW + "No master password set. Please create one.")
            self.set_master_password()
        return False

    def set_master_password(self):
        master_password = getpass.getpass(Fore.YELLOW + "Create Master Password: ")
        confirm_password = getpass.getpass(Fore.YELLOW + "Confirm Master Password: ")
        if master_password == confirm_password:
            hashed_password = self.password_manager.hash_master_password(master_password)
            key = self.password_manager.generate_key()
            encrypted_key = self.password_manager.store_encryption_key(key, hashed_password)
            self.db_manager.execute_query("INSERT INTO master_info (master_password_hash, encryption_key, failed_attempts) VALUES (?, ?, 0)",
                                          (hashed_password, encrypted_key))
            print(Fore.GREEN + "Master password set successfully!")
            return True  # Indicate success
        else:
            print(Fore.RED + "Passwords do not match. Please try again.")
            return False  # Indicate failure

    def cli_menu(self):
        print(Fore.CYAN + """
            ======================================
                   PASSWORD MANAGER CLI          
            ======================================
            1. Add New Password
            2. View All Websites
            3. View Password for a Website
            4. Delete Password
            5. Exit
        """)
        return input(Fore.YELLOW + "Enter your choice: " + Style.RESET_ALL)

    def main(self):
        if not self.login():
            if not self.set_master_password():
                sys.exit("Exiting...")  # Exit if setting the password fails

        while True:
            choice = self.cli_menu()
            if choice == "1":
                while True:
                    website = input(Fore.YELLOW + "Website: ")
                    username = input(Fore.YELLOW + "Username: ")
                    password = getpass.getpass(Fore.YELLOW + "Password: ")
                    name = input(Fore.YELLOW + "Name (optional): ")
                    email = input(Fore.YELLOW + "Email (optional): ")
                    custom_field = input(Fore.YELLOW + "Custom Field (optional): ")
                    if self.password_manager.add_password(website, username, password, self.key, name, email, custom_field):
                        print(Fore.GREEN + "Password added successfully!")
                        break  # Exit the loop after adding the password

                continue  # This will go back to the main menu and allow the user to choose to view websites

            elif choice == "2":
                websites = self.password_manager.view_websites()
                if websites:
                    print(Fore.CYAN + "Stored websites:")
                    for website in websites:
                        print(Fore.YELLOW + f"- {website[0]}")
                else:
                    print(Fore.RED + "No websites stored.")

                sub_choice = self.view_websites_menu()
                if sub_choice == "1":
                    continue  # Go back to the main menu
                elif sub_choice == "2":
                    website = input(Fore.YELLOW + "Enter website: ")
                    password_info = self.password_manager.view_password(website, self.key)
                    if password_info:
                        print(Fore.GREEN + f"Password for {website}: {password_info['password']}")
                        print(Fore.GREEN + f"Name: {password_info['name'] if password_info['name'] else 'N/A'}")
                        print(Fore.GREEN + f"Email: {password_info['email'] if password_info['email'] else 'N/A'}")
                        print(Fore.GREEN + f"Custom Field: {password_info['custom_field'] if password_info['custom_field'] else 'N/A'}")
                    else:
                        print(Fore.RED + "No password found for this website.")

                elif sub_choice == "3":
                    website = input(Fore.YELLOW + "Enter the website name to delete: ")
                    
                    # Check if the website exists before asking for the master password
                    if not self.password_manager.db_manager.fetch_one("SELECT 1 FROM credentials WHERE website = ?", (website,)):
                        print(Fore.RED + f"Website '{website}' does not exist. Deletion aborted.")
                        continue  # Go back to the main menu

                    master_password = getpass.getpass(Fore.YELLOW + "Enter Master Password to confirm deletion: ")
                    if self.password_manager.delete_password(website, self.key, master_password):
                        print(Fore.GREEN + "Password deleted successfully.")
                    else:
                        print(Fore.RED + "Failed to delete password.")

                elif sub_choice == "4":
                    print(Fore.YELLOW + "Exiting...")
                    break

            elif choice == "3":
                website = input(Fore.YELLOW + "Enter website: ")
                password_info = self.password_manager.view_password(website, self.key)
                if password_info:
                    print(Fore.GREEN + f"Password for {website}: {password_info['password']}")
                    print(Fore.GREEN + f"Name: {password_info['name'] if password_info['name'] else 'N/A'}")
                    print(Fore.GREEN + f"Email: {password_info['email'] if password_info['email'] else 'N/A'}")
                    print(Fore.GREEN + f"Custom Field: {password_info['custom_field'] if password_info['custom_field'] else 'N/A'}")
                else:
                    print(Fore.RED + "No password found for this website.")

            elif choice == "4":
                website = input(Fore.YELLOW + "Enter the website name to delete: ")
                # Check if the website exists before asking for the master password
                if not self.password_manager.db_manager.fetch_one("SELECT 1 FROM credentials WHERE website = ?", (website,)):
                    print(Fore.RED + f"Website '{website}' does not exist. Deletion aborted.")
                    continue  # Go back to the main menu

                master_password = getpass.getpass(Fore.YELLOW + "Enter Master Password to confirm deletion: ")
                if self.password_manager.delete_password(website, self.key, master_password):
                    print(Fore.GREEN + "Password deleted successfully.")
                else:
                    print(Fore.RED + "Failed to delete password.")

            elif choice == "5":
                print(Fore.YELLOW + "Exiting...")
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again.")

    def add_password_menu(self):
        print(Fore.CYAN + """
            ======================================
                   ADD PASSWORD MENU          
            ======================================
            1. Add Another Password
            2. View All Websites
            3. View Password for a Website
            4. Delete Password
            5. Exit
        """)
        return input(Fore.YELLOW + "Enter your choice: " + Style.RESET_ALL)

    def view_websites_menu(self):
        print(Fore.CYAN + """
            ======================================
                   VIEW WEBSITES MENU          
            ======================================
            1. Go back to Home Menu
            2. View Password for a Website
            3. Delete Password
            4. Exit
        """)
        return input(Fore.YELLOW + "Enter your choice: " + Style.RESET_ALL)

    def view_password_menu(self):
        print(Fore.CYAN + """
            ======================================
                   VIEW PASSWORD MENU          
            ======================================
            1. Go back to Home Menu
            2. Delete Password
            3. Exit
        """)
        return input(Fore.YELLOW + "Enter your choice: " + Style.RESET_ALL)

if __name__ == "__main__":
    cli = CLI()
    cli.main()


