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
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_info (id INTEGER PRIMARY KEY, master_password_hash TEXT, failed_attempts INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, website TEXT, username TEXT, encrypted_password TEXT)''')
    conn.commit()
    conn.close()

# Generate encryption key using Fernet
def generate_key():
    key = base64.urlsafe_b64encode(Fernet.generate_key())
    return key

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
    if result:
        encrypted_password = result[0]
        decrypted_password = decrypt_password(encrypted_password, key)
        print(f"Password for {website}: {decrypted_password}")
    else:
        print("No password found for this website.")
    conn.close()

# Handle the login process
def login():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT master_password_hash, failed_attempts FROM master_info")
    result = cursor.fetchone()
    
    if result:
        stored_hash, failed_attempts = result
        
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
                conn.close()
                return True
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
    return False

# Set the master password for the first time
def set_master_password():
    conn = connect_db()
    cursor = conn.cursor()
    master_password = getpass.getpass("Create Master Password: ")
    confirm_password = getpass.getpass("Confirm Master Password: ")
    
    if master_password == confirm_password:
        hashed_password = hash_master_password(master_password)
        cursor.execute("INSERT INTO master_info (master_password_hash, failed_attempts) VALUES (?, 0)", (hashed_password,))
        conn.commit()
        print("Master password set successfully!")
    else:
        print("Passwords do not match. Please try again.")
    
    conn.close()

# Show CLI options
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
    if not login():
        sys.exit("Exiting...")
    
    # CLI Main Loop
    while True:
        choice = cli_menu()
        if choice == "1":
            website = input("Website: ")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            key = generate_key()
            add_password(website, username, password, key)
            print("Password added successfully!")
        elif choice == "2":
            websites = view_websites()
            for website in websites:
                print(website[0])
        elif choice == "3":
            website = input("Enter website: ")
            master_password = getpass.getpass("Master Password: ")
            key = generate_key()
            view_password(website, master_password, key)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
