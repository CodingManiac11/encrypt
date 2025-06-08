# Encrypted Messenger App

## Project Description

This is a mock encrypted messaging application built with Python (Flask) for the backend and HTML/CSS/JavaScript for the frontend. The application emphasizes secure communication by implementing RSA encryption for messages, ensuring that messages are decrypted only on the receiver's side. It features user authentication, real-time chat capabilities, and a user-friendly interface inspired by modern messaging apps like WhatsApp.

## Features

-   **User Authentication**: Secure user registration and login with usernames and passwords.
-   **RSA Encryption**: Messages are encrypted using RSA asymmetric encryption before being stored in the database and sent over the network.
-   **Client-Side Decryption**: Received messages are initially displayed in their encrypted form. Receivers can explicitly decrypt messages using a dedicated "Decrypt" button, ensuring privacy.
-   **Real-time Messaging**: Powered by Flask-SocketIO for instant message delivery and real-time updates.
-   **Message History**: Stores message history in a SQLite database (`chat.db`).
-   **Modern User Interface**: A clean, responsive chat interface with message bubbles and a WhatsApp-like design, including a dark mode option.
-   **Typing Indicators**: Shows when another user is typing.

## Tech Stack

-   **Backend**: Python (Flask, Flask-SocketIO, Flask-SQLAlchemy, Cryptography, PyJWT, python-dotenv)
-   **Database**: SQLite (`chat.db`)
-   **Frontend**: HTML5, CSS (Tailwind CSS via CDN), JavaScript (Socket.IO client, Web Crypto API)

## Setup Instructions

Follow these steps to set up and run the application locally:

### Prerequisites

-   Python 3.7+ (recommended)
-   `pip` (Python package installer)

### 1. Clone the Repository (or ensure you are in the project directory)

If you haven't already, ensure you are in the correct project directory where `app.py`, `requirements.txt`, and the `templates` folder are located.

```bash
cd /path/to/your/project/directory
```

### 2. Clean Up Previous Installations and Database (Crucial Step!)

To ensure a fresh and correct setup, it's essential to remove any old database files or compiled Python bytecode that might cause conflicts.

-   **Delete the database file**: If a `chat.db` file exists from previous runs, delete it. This ensures the database schema is correctly created with all necessary columns (like `password`).

    ```bash
    # For Windows PowerShell
    Remove-Item -Path .\chat.db -Force -ErrorAction SilentlyContinue

    # For Linux/macOS (or Git Bash on Windows)
    rm -f chat.db
    ```

-   **Delete Python bytecode cache**: Remove the `__pycache__` directory if it exists.

    ```bash
    # For Windows PowerShell
    Remove-Item -Path .\__pycache__ -Recurse -Force -ErrorAction SilentlyContinue

    # For Linux/macOS (or Git Bash on Windows)
    rm -rf __pycache__
    ```

### 3. Install Dependencies

Install all required Python packages from the `requirements.txt` file. This step will also ensure that `eventlet` (which caused compatibility issues) is not installed.

```bash
pip install -r requirements.txt
```

### 4. Run the Application

Start the Flask development server:

```bash
python app.py
```

If the server starts successfully, you will see output similar to this in your terminal:

```
Database tables created successfully
 * Serving Flask app 'app' (lazy loading)
 * Environment: development
 * Debug mode: on
 * Running on http://127.0.0.1:8080/ (Press CTRL+C to quit)
```

### 5. Access the Application

Open your web browser and navigate to:

[http://127.0.0.1:8080/](http://127.0.0.1:8080/)

## Usage

1.  **Register**: On the welcome screen, enter a unique username and a password, then click "Register".
2.  **Login**: After registration (or if you already have an account), enter your username and password, then click "Login".
3.  **Select a User**: From the dropdown list, select another registered user to start a chat.
4.  **Send Messages**: Type your message in the input box and click the send button (paper plane icon) or press Enter.
    -   Messages you send will appear on the right, initially displaying as `[object ArrayBuffer]` or a Base64 string, with an "Encrypted (sent)" label.
5.  **Receive Messages**: Messages from other users will appear on the left, also initially encrypted.
6.  **Decrypt Messages**: For received messages, click the "Decrypt" button to reveal the original content. The label will change to "Decrypted".
7.  **Dark Mode**: Use the moon icon in the header to toggle between light and dark themes.

## Encryption Details

This application uses RSA asymmetric encryption provided by the `cryptography` library in Python and the Web Crypto API in JavaScript.

-   **Key Generation**: Each user generates a unique pair of RSA public and private keys upon registration.
-   **Encryption Process**: When you send a message, it is encrypted using the *recipient's public key*. This means only the recipient (who possesses the corresponding private key) can decrypt the message.
-   **Storage**: Encrypted messages are stored in the `chat.db` SQLite database.
-   **Decryption Process**: The receiver's browser, upon clicking the "Decrypt" button, uses the receiver's private key (securely passed during login) to decrypt the message locally.

### Screenshots
![image](https://github.com/user-attachments/assets/d27e608b-161b-485d-93ae-4783b5cebe20)
![image](https://github.com/user-attachments/assets/23ddbb7b-31e8-424d-8b92-4cfd269da869)
![image](https://github.com/user-attachments/assets/b7e56961-4fb2-46fb-93f1-595593ff166b)



## Troubleshooting

-   **`AttributeError: 'SocketIO' object has no attribute 'wsgi_app'` or `ssl.wrap_socket` errors**: This indicates an outdated `app.py` file or a lingering `eventlet` installation. Follow the "Clean Up Previous Installations and Database" steps rigorously, especially deleting `__pycache__` and `chat.db`, then reinstall dependencies.
-   **"Registration failed"**: Check your terminal for backend error messages. Ensure username and password fields are not empty, and the username is not already taken.
-   **"Decryption failed!" / `[object ArrayBuffer]` messages**: Ensure your `app.py` is up-to-date with the Base64 encoding for encrypted messages and that the login route sends the `private_key`. Perform a hard refresh (`Ctrl+Shift+R` or `Cmd+Shift+R`) in your browser. Check your browser's console (F12) for `InvalidCharacterError` or other JavaScript errors.
-   **`ERR_CONNECTION_REFUSED`**: Ensure your Flask server is running in the terminal. The URL should be `http://127.0.0.1:8080/`.

If issues persist, try running `pip install -r requirements.txt --upgrade` to ensure all packages are updated.
