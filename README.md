# Password Manager CLI

A secure command-line password manager built with Python, SQLite, and bcrypt.

## Features
- Master password protection
- Store and encrypt passwords
- View, edit, and delete passwords
- Automatically deletes passwords after 10 failed login attempts

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/password-manager.git
    cd password-manager
    ```

2. Set up the virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Run the password manager:
    ```bash
    python password_manager.py
    ```

## Deployment

To create a standalone executable, use PyInstaller:
```bash
pyinstaller --onefile password_manager.py
```

This will create an executable in the dist/ folder.

Security
Passwords are encrypted using the cryptography library.
The master password is hashed with bcrypt.
Passwords are deleted after 10 incorrect login attempts.
markdown
Copy code

### Step 7: Initialize a Git Repository and Push to GitHub

1. **Initialize Git**:
    ```bash
    git init
    ```

2. **Add and commit files**:
    ```bash
    git add .
    git commit -m "Initial commit for password manager project"
    ```

3. **Create a GitHub repository**:
    - Go to GitHub and create a new repository (you can name it something like `password-manager`).
    - Copy the repository URL.

4. **Push to GitHub**:
    ```bash
    git remote add origin https://github.com/yourusername/password-manager.git
    git push -u origin master
    ```

### Step 8: Deploy as an Executable

Once your app is ready, you can use PyInstaller to bundle it into an executable.

1. **Install PyInstaller**:
    If you haven't already installed it, you can do so with:
    ```bash
    pip install pyinstaller
    ```

2. **Create the executable**:
    Run the following command:
    ```bash
    pyinstaller --onefile password_manager.py
    ```

3. **Locate the executable**:
    After running PyInstaller, you’ll find the executable in the `dist/` folder. You can now distribute this as a standalone executable for others to use without needing Python installed.

---
