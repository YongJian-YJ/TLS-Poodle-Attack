import streamlit as st
import os
import hmac
import hashlib

block_size = 16
key_size = 32

# Initialize session state variables
if "ciphertext_username" not in st.session_state:
    st.session_state["ciphertext_username"] = ""

if "key_username" not in st.session_state:
    st.session_state["key_username"] = ""

if "iv_username" not in st.session_state:
    st.session_state["iv_username"] = ""

if "ciphertext_password" not in st.session_state:
    st.session_state["ciphertext_password"] = ""

if "key_password" not in st.session_state:
    st.session_state["key_password"] = ""

if "iv_password" not in st.session_state:
    st.session_state["iv_password"] = ""

st.header("Registration Page")


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def pad(plaintext, block_size):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


def cbc_encrypt(plaintext, key, iv, block_size):
    """Encrypt using CBC mode."""
    # Gets the has code
    hash_value = hmac.new(key, plaintext, hashlib.sha256).digest()
    # Appends the hash code (HMAC) to the raw plaintext data
    print("HMAC:", hash_value)
    print(len(hash_value))
    combined_plaintext = plaintext + hash_value
    print("plaintext:", combined_plaintext)
    padded_plaintext = pad(combined_plaintext, block_size)
    print("padded_plaintext:", padded_plaintext)
    previous = iv
    ciphertext = b""

    # Simulated encryption using XOR
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i : i + block_size]
        cipher_block = xor_bytes(previous, block)  
        ciphertext += cipher_block
        previous = cipher_block

    return ciphertext


# Create a textbox for Alice to type the message
username_input = st.text_input("Username:")
password_input = st.text_input("Password:", type="password")


# Create a button to send the message
if st.button("Register"):
    secret_username = username_input.encode("utf-8")
    secret_password = password_input.encode("utf-8")

    # Generate keys for username
    iv_username = os.urandom(block_size)
    key_username = os.urandom(key_size)
    print("key username:", key_username)
    # print(type(key_username))
    key_username_int = int.from_bytes(key_username, byteorder="big")
    print(key_username_int)
    # print(key_username_int.bit_length(), "bits")

    # Generate keys for password
    iv_password = os.urandom(block_size)
    key_password = os.urandom(key_size)
    print("key password:", key_password)
    key_password_int = int.from_bytes(key_password, byteorder="big")
    print(key_password_int)
    # print(type(key_password))

    # Store IV and key in session state
    st.session_state["iv_username"] = iv_username
    st.session_state["iv_password"] = iv_password
    st.session_state["key_username"] = key_username
    st.session_state["key_password"] = key_password

    # Perform CBC encryption
    ciphertext_username = cbc_encrypt(
        secret_username, key_username, iv_username, block_size
    )
    ciphertext_password = cbc_encrypt(
        secret_password, key_password, iv_password, block_size
    )

    # Store ciphertext in session state
    st.session_state["ciphertext_username"] = ciphertext_username
    st.session_state["ciphertext_password"] = ciphertext_password

    # Display information
    st.success("Account registered successfully!")
    st.markdown(
        f"""
    Please confirm that your password is: `{secret_password.decode('utf-8')}`

    \nYour username is: `{ciphertext_username.hex()}`  
    Your password is: `{ciphertext_password.hex()}`
    """
    )
