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

# Connect to SQLite database
def connect_db():
    return sqlite3.connect(DB_FILE)

# Create necessary tables
def create_tables():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_info (id INTEGER PRIMARY KEY, master_password_hash TEXT, encryption_key BLOB, failed_attempts INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, website TEXT, username TEXT, encrypted_password TEXT)''')
    conn.commit()
    conn.close()

# Generate encryption key using Fernet (proper 32 byte key)
def generate_key():
    return Fernet.generate_key()

# Encrypt password
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt password
def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Hash master password using bcrypt
def hash_master_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Check if master password is correct
def check_master_password(input_password, stored_hash):
    return bcrypt.checkpw(input_password.encode(), stored_hash)

# Store the encryption key securely (encrypted using master password)
def store_encryption_key(key, master_password_hash):
    cipher_suite = Fernet(base64.urlsafe_b64encode(master_password_hash[:32]))
    encrypted_key = cipher_suite.encrypt(key)
    return encrypted_key

# Retrieve the encryption key securely (decrypt using master password)
def retrieve_encryption_key(encrypted_key, master_password_hash):
    cipher_suite = Fernet(base64.urlsafe_b64encode(master_password_hash[:32]))
    key = cipher_suite.decrypt(encrypted_key)
    return key

# Add new password to database
def add_password(website, username, password, key):
    conn = connect_db()
    cursor = conn.cursor()
    encrypted_password = encrypt_password(password, key)
    cursor.execute("INSERT INTO credentials (website, username, encrypted_password) VALUES (?, ?, ?)",
                   (website, username, encrypted_password))
    conn.commit()
    conn.close()

# View stored websites
def view_websites():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT website FROM credentials")
    websites = cursor.fetchall()
    conn.close()
    return websites

# View password for a website
def view_password(website, master_password, key):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password FROM credentials WHERE website = ?", (website,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        encrypted_password = result[0]
        decrypted_password = decrypt_password(encrypted_password, key)
        print(f"Password for {website}: {decrypted_password}")
    else:
        print("No password found for this website.")

# Handle the login process
def login():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_password_hash, encryption_key, failed_attempts FROM master_info")
    result = cursor.fetchone()
    
    if result:
        stored_hash, encrypted_key, failed_attempts = result
        
        if failed_attempts >= 10:
            print("Too many failed attempts. Deleting all passwords...")
            cursor.execute("DELETE FROM credentials")
            cursor.execute("UPDATE master_info SET failed_attempts = 0")
            conn.commit()
            conn.close()
            sys.exit(0)
        
        for attempt in range(10):
            master_password = getpass.getpass("Enter Master Password: ")
            if check_master_password(master_password, stored_hash):
                cursor.execute("UPDATE master_info SET failed_attempts = 0")
                conn.commit()
                print("Login successful!")
                # Retrieve the encryption key securely
                key = retrieve_encryption_key(encrypted_key, stored_hash)
                conn.close()
                return key
            else:
                cursor.execute("UPDATE master_info SET failed_attempts = failed_attempts + 1")
                conn.commit()
                print(f"Incorrect password. Attempt {attempt + 1}/10")
        
        conn.close()
        sys.exit("Too many failed attempts. Exiting...")
    else:
        print("No master password set. Please create one.")
        set_master_password()
    conn.close()
    return None

# Set the master password for the first time
def set_master_password():
    conn = connect_db()
    cursor = conn.cursor()
    master_password = getpass.getpass("Create Master Password: ")
    confirm_password = getpass.getpass("Confirm Master Password: ")
    
    if master_password == confirm_password:
        hashed_password = hash_master_password(master_password)
        key = generate_key()  # Generate Fernet encryption key
        encrypted_key = store_encryption_key(key, hashed_password)  # Encrypt Fernet key using master password hash
        cursor.execute("INSERT INTO master_info (master_password_hash, encryption_key, failed_attempts) VALUES (?, ?, 0)", (hashed_password, encrypted_key))
        conn.commit()
        print("Master password set successfully!")
        conn.close()
        sys.exit(0)  # Exit after setting the master password
    else:
        print("Passwords do not match. Please try again.")
    
    conn.close()

# Show CLI options once
def cli_menu():
    print("""
        ======================================
               PASSWORD MANAGER CLI          
        ======================================
        1. Add New Password
        2. View All Websites
        3. View Password for a Website
        4. Exit
    """)
    choice = input("Enter your choice: ")
    return choice

def main():
    create_tables()
    
    # Login or set master password
    key = login()
    if not key:
        sys.exit("Exiting...")
    
    # CLI Main Loop
    while True:
        choice = cli_menu()  # Show menu only once
        if choice == "1":
            website = input("Website: ")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            add_password(website, username, password, key)
            print("Password added successfully!")
        elif choice == "2":
            websites = view_websites()
            if websites:
                print("Stored websites:")
                for website in websites:
                    print(f"- {website[0]}")
            else:
                print("No websites stored.")
        elif choice == "3":
            website = input("Enter website: ")
            master_password = getpass.getpass("Master Password: ")
            view_password(website, master_password, key)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")
            continue  # Go back to the main menu if invalid choice

if __name__ == "__main__":
    main()
