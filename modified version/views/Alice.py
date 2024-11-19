import streamlit as st
import os
import base64

block_size = 8

# Initialize session state variables
if "ciphertext_username" not in st.session_state:
    st.session_state["ciphertext_username"] = ""
if "ciphertext_password" not in st.session_state:
    st.session_state["ciphertext_password"] = ""

st.header("Registration Page")

# Initialize session state variables
if "message" not in st.session_state:
    st.session_state["message"] = ""
if "key" not in st.session_state:
    st.session_state["key"] = os.urandom(block_size)


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def pad(plaintext, block_size=8):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


def cbc_encrypt(plaintext, key, iv, block_size=8):
    """Encrypt using CBC mode."""
    plaintext = pad(plaintext, block_size)
    previous = iv
    ciphertext = b""

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        cipher_block = xor_bytes(previous, block)  # Simulated encryption using XOR
        ciphertext += cipher_block
        previous = cipher_block

    return ciphertext


# Create a textbox for Alice to type the message
username_input = st.text_input("Username:")
password_input = st.text_input("Password:")


# Create a button to send the message
if st.button("Register"):
    secret_username = username_input.encode("utf-8")
    secret_password = password_input.encode("utf-8")

    # Generate keys for username
    iv_username = os.urandom(block_size)
    key_username = os.urandom(block_size)

    # Generate keys for password
    iv_password = os.urandom(block_size)
    key_password = os.urandom(block_size)

    # Store IV and key in session state
    st.session_state["iv_username"] = iv_username
    st.session_state["iv_password"] = iv_password
    st.session_state["key_username"] = key_username
    st.session_state["key_password"] = key_password

    # Perform CBC encryption
    ciphertext_username = cbc_encrypt(secret_username, key_username, iv_username)
    ciphertext_password = cbc_encrypt(secret_password, key_password, iv_password)

    # Store ciphertext in session state
    st.session_state["ciphertext_username"] = ciphertext_username
    st.session_state["ciphertext_password"] = ciphertext_password

    # Display information
    st.success("Account registered successfully!")
    st.markdown(
        f"""
    Your username is: `{ciphertext_username.hex()}`  
    Your password is: `{ciphertext_password.hex()}`
    """
    )
