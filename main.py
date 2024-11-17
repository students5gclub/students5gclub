import streamlit as st
import sqlite3
from bcrypt import hashpw, gensalt, checkpw


# Initialize Database
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# Hash Password
def hash_password(password):
    return hashpw(password.encode("utf-8"), gensalt())


# Check Password
def verify_password(stored_password, provided_password):
    return checkpw(provided_password.encode("utf-8"), stored_password)


# Add User to Database
def add_user(full_name, email, password):
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)",
            (full_name, email, hash_password(password))
        )
        conn.commit()
        conn.close()
        return True, "🎉 Registration successful! Welcome to the Students 5G Club!"
    except sqlite3.IntegrityError:
        return False, "❌ Email already exists. Please try with a different email."


# Authenticate User
def authenticate_user(email, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT full_name, password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and verify_password(user[1], password):
        return True, user[0]
    return False, None


# Main App
def main():
    # Header
    st.title("🎓 Students 5G Club")

    # Menu
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Create a New Account")
        full_name = st.text_input("Full Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if not full_name or not email or not password or not confirm_password:
                st.error("⚠️ Please fill out all fields.")
            elif password != confirm_password:
                st.error("⚠️ Passwords do not match. Please try again.")
            else:
                success, message = add_user(full_name, email, password)
                if success:
                    st.success(message)
                else:
                    st.error(message)

    elif choice == "Login":
        st.subheader("Login to Your Account")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if not email or not password:
                st.error("⚠️ Please fill out all fields.")
            else:
                authenticated, full_name = authenticate_user(email, password)
                if authenticated:
                    st.success(f"Welcome back, {full_name}!")
                    # Add logic for what happens after login
                    st.write("You can now access your dashboard.")
                else:
                    st.error("❌ Invalid email or password. Please try again.")


if __name__ == "__main__":
    init_db()
    main()
