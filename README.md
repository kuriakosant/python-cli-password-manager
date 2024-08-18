# Python CLI Password Manager

## Overview

The **Python CLI Password Manager** is a command-line tool designed to securely manage passwords. Users can store, view, edit, and delete passwords for various services in a local SQLite database. All passwords are encrypted using AES encryption (`Fernet` from the `cryptography` library), and the master password is hashed using `bcrypt` for added security. After 10 incorrect master password attempts, all stored passwords will be deleted to prevent unauthorized access.

### Key Features:

- **Master Password**: Required for accessing the password manager.
- **Password Encryption**: Passwords are encrypted using `Fernet` and stored securely in an SQLite database.
- **Add/View/Delete Passwords**: Easily manage passwords for different services.
- **Session Security**: Each time you want to view a password, you must re-enter the master password.
- **Failed Attempts Protection**: All passwords are deleted after 10 incorrect master password attempts.

---

## Installation

Follow these steps to install and run the password manager.

### 1. Clone the Repository

First, clone the repository from GitHub to your local machine:

`git clone https://github.com/kuriakosant/python-cli-password-manager`

### 2. Set Up a Virtual Environment (Optional but Recommended)

It’s recommended to create a virtual environment to isolate dependencies:

`python3 -m venv venv`

## 3. Activate the virtual environment (Linux/macOS)

`source venv/bin/activate`

# Activate the virtual environment (Windows)

`.\venv\Scripts\activate`

### 3. Install Dependencies

All required dependencies are listed in the `requirements.txt` file. Install them using `pip`:

`pip install -r requirements.txt`

This will install:

- **bcrypt**: For secure password hashing.
- **cryptography**: For AES encryption and decryption (using `Fernet`).
- **pyfiglet**: For displaying ASCII art in the terminal.

---

## Executable Version

The **Python CLI Password Manager** is also available as a standalone executable for easy use without requiring Python or any dependencies to be installed.

### Available Formats

- **Windows**: `password_manager.exe`
- **Linux**: `password_manager` (ELF format)

### Running the Executable

1. **Download the Executable**:

   - Obtain the `password_manager.exe` (for Windows) or `password_manager` (for Linux) from the [releases page](https://github.com/kuriakosant/python-cli-password-manager/releases).

2. **For Linux Users**:

   - Open a terminal and navigate to the directory where the executable is located:
     ```sh
     cd /path/to/directory
     ```
   - Set the executable permissions (if necessary):
     ```sh
     chmod +x password_manager
     ```
   - Run the application:
     ```sh
     ./password_manager
     ```

3. **For Windows Users**:
   - Simply double-click the `password_manager.exe` file to run the application.

### Note

- The first time you run the application, it will create a `password_manager.db` file in the same directory to store your passwords securely.
- Ensure that you keep the `password_manager.db` file safe, as it contains your stored passwords.

---
