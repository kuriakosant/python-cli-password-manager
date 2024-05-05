import bcrypt
import sqlite3
import os
from cryptography.fernet import Fernet
from getpass import getpass
import pyfiglet

# Initialize database
def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords 
                      (id INTEGER PRIMARY KEY, service TEXT, username TEXT, password BLOB)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS master_password
                      (id INTEGER PRIMARY KEY, password_hash BLOB)''')
    conn.commit()
    conn.close()

# Hash the master password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check master password
def check_password(stored_hash, entered_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash)

# Store master password in DB
def set_master_password():
    password = getpass("Set your master password: ")
    hashed_password = hash_password(password)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO master_password (password_hash) VALUES (?)", (hashed_password,))
    conn.commit()
    conn.close()

# Check if master password is set
def is_master_password_set():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master_password")
    result = cursor.fetchone()
    conn.close()
    return result is not None

# Add a new password entry
def add_password(master_key):
    service = input("Enter service name: ")
    username = input("Enter username: ")
    password = getpass("Enter password: ")

    # Encrypt password
    fernet = Fernet(master_key)
    encrypted_password = fernet.encrypt(password.encode('utf-8'))

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)", 
                   (service, username, encrypted_password))
    conn.commit()
    conn.close()

# View stored passwords
def view_passwords(master_key):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT service, username, password FROM passwords")
    rows = cursor.fetchall()

    fernet = Fernet(master_key)
    
    for row in rows:
        service, username, encrypted_password = row
        password = fernet.decrypt(encrypted_password).decode('utf-8')
        print(f"Service: {service}, Username: {username}, Password: {password}")

    conn.close()

# Handle login attempts
def login():
    failed_attempts = 0

    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM master_password")
    stored_password_hash = cursor.fetchone()[0]
    
    while failed_attempts < 10:
        entered_password = getpass("Enter master password: ")
        if check_password(stored_password_hash, entered_password):
            return entered_password
        else:
            failed_attempts += 1
            print(f"Incorrect password. Attempts left: {10 - failed_attempts}")

    # Delete all stored passwords after 10 failed attempts
    cursor.execute("DELETE FROM passwords")
    conn.commit()
    conn.close()
    print("All passwords deleted due to too many incorrect attempts.")
    exit()

# Generate ASCII art lock
def show_ascii_art():
    ascii_art = pyfiglet.figlet_format("Lock")
    print(ascii_art)

# Main program loop
def main():
    init_db()

    if not is_master_password_set():
        set_master_password()
    
    master_password = login()

    # Generate key for encryption
    master_key = Fernet.generate_key()

    while True:
        show_ascii_art()
        print("1. Add password")
        print("2. View passwords")
        print("3. Exit")

        choice = input("Choose an option: ")
        
        if choice == "1":
            add_password(master_key)
        elif choice == "2":
            view_passwords(master_key)
        elif choice == "3":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
