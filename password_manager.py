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
            print(f"Website '{website}' already exists. Please use a different name.")
            return False
        encrypted_password = self.encrypt_password(password, key)
        self.db_manager.execute_query("INSERT INTO credentials (website, username, encrypted_password, name, email, custom_field) VALUES (?, ?, ?, ?, ?, ?)",
                                      (website, username, encrypted_password, name, email, custom_field))
        return True

    def view_websites(self):
        return self.db_manager.fetch_all("SELECT website FROM credentials")

    def view_password(self, website, key):
        result = self.db_manager.fetch_one("SELECT encrypted_password FROM credentials WHERE website = ?", (website,))
        if result:
            encrypted_password = result[0]
            return self.decrypt_password(encrypted_password, key)
        else:
            return None

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
                print("Too many failed attempts. Deleting all passwords...")
                self.db_manager.execute_query("DELETE FROM credentials")
                self.db_manager.execute_query("UPDATE master_info SET failed_attempts = 0")
                sys.exit(0)

            for attempt in range(10):
                master_password = getpass.getpass("Enter Master Password: ")
                if self.password_manager.check_master_password(master_password, stored_hash):
                    self.db_manager.execute_query("UPDATE master_info SET failed_attempts = 0")
                    print("Login successful!")
                    self.key = self.password_manager.retrieve_encryption_key(encrypted_key, stored_hash)
                    return True
                else:
                    self.db_manager.execute_query("UPDATE master_info SET failed_attempts = failed_attempts + 1")
                    print(f"Incorrect password. Attempt {attempt + 1}/10")

            sys.exit("Too many failed attempts. Exiting...")
        else:
            print("No master password set. Please create one.")
            self.set_master_password()
        return False

    def set_master_password(self):
        master_password = getpass.getpass("Create Master Password: ")
        confirm_password = getpass.getpass("Confirm Master Password: ")
        if master_password == confirm_password:
            hashed_password = self.password_manager.hash_master_password(master_password)
            key = self.password_manager.generate_key()
            encrypted_key = self.password_manager.store_encryption_key(key, hashed_password)
            self.db_manager.execute_query("INSERT INTO master_info (master_password_hash, encryption_key, failed_attempts) VALUES (?, ?, 0)",
                                          (hashed_password, encrypted_key))
            print("Master password set successfully!")
            sys.exit(0)
        else:
            print("Passwords do not match. Please try again.")

    def cli_menu(self):
        print("""
            ======================================
                   PASSWORD MANAGER CLI          
            ======================================
            1. Add New Password
            2. View All Websites
            3. View Password for a Website
            4. Exit
        """)
        return input("Enter your choice: ")

    def add_password_menu(self):
        print("""
            ======================================
                   PASSWORD MANAGER CLI          
            ======================================
            1. Add Another Password
            2. View All Websites
            3. View Password for a Website
            4. Exit
        """)
        return input("Enter your choice: ")

    def view_websites_menu(self):
        print("""
            ======================================
                   PASSWORD MANAGER CLI          
            ======================================
            1. Go back to Home Menu
            2. View Password for a Website
            3. Exit
        """)
        return input("Enter your choice: ")

    def view_password_menu(self):
        print("""
            ======================================
                   PASSWORD MANAGER CLI          
            ======================================
            1. Go back to Home Menu
            2. Exit
        """)
        return input("Enter your choice: ")

    def main(self):
        if not self.login():
            sys.exit("Exiting...")

        while True:
            choice = self.cli_menu()
            if choice == "1":
                while True:
                    website = input("Website: ")
                    username = input("Username: ")
                    password = getpass.getpass("Password: ")
                    name = input("Name (optional): ")
                    email = input("Email (optional): ")
                    custom_field = input("Custom Field (optional): ")
                    if self.password_manager.add_password(website, username, password, self.key, name, email, custom_field):
                        print("Password added successfully!")

                    sub_choice = self.add_password_menu()
                    if sub_choice == "1":
                        continue
                    elif sub_choice in ["2", "3"]:
                        break
                    elif sub_choice == "4":
                        sys.exit("Exiting...")

            elif choice == "2":
                while True:
                    websites = self.password_manager.view_websites()
                    if websites:
                        print("Stored websites:")
                        for website in websites:
                            print(f"- {website[0]}")
                    else:
                        print("No websites stored.")

                    sub_choice = self.view_websites_menu()
                    if sub_choice == "1":
                        break
                    elif sub_choice == "2":
                        break
                    elif sub_choice == "3":
                        sys.exit("Exiting...")

            elif choice == "3":
                while True:
                    website = input("Enter website: ")
                    password = self.password_manager.view_password(website, self.key)
                    if password:
                        print(f"Password for {website}: {password}")
                    else:
                        print("No password found for this website.")

                    sub_choice = self.view_password_menu()
                    if sub_choice == "1":
                        break
                    elif sub_choice == "2":
                        sys.exit("Exiting...")

            elif choice == "4":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    cli = CLI()
    cli.main()


