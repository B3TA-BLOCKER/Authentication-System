import sqlite3
import bcrypt
import os

# Use environment variables for admin credentials
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "password123")

conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
conn.commit()

def authenticate(username, password):
    try:
        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                print("Admin login successful!")
            else:
                print("User login successful!")
            return True
        else:
            print("Invalid credentials!")
            return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def register_user(username, password):
    if len(username) > 255 or len(password) > 255:
        print("Input too long!")
        return
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
        conn.commit()
        print("User registered successfully!")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

# Main logic
print("1. Register\n2. Login")
choice = input("Enter choice: ")

if choice == "1":
    user = input("Enter username: ")
    pwd = input("Enter password: ")
    register_user(user, pwd)
elif choice == "2":
    user = input("Enter username: ")
    pwd = input("Enter password: ")
    authenticate(user, pwd)
else:
