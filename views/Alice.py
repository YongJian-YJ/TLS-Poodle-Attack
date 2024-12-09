import streamlit as st
import os
import hmac, hashlib

# Define ciphertext block size and key size for encryption / decryption, according to Advanced Encryption Standard (AES).
block_size = 16
key_size = 32

# Initialize session state variables
if ("ciphertext_username" and "key_username" and "iv_username") not in st.session_state:
    st.session_state["ciphertext_username"] = ""
    st.session_state["key_username"] = ""
    st.session_state["iv_username"] = ""

if ("ciphertext_password" and "key_password" and "iv_password") not in st.session_state:
    st.session_state["ciphertext_password"] = ""
    st.session_state["key_password"] = ""
    st.session_state["iv_password"] = ""


# Function to simulate encryption via XOR operation between two byte-like objects (for demo purposes only)
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# Function to pad the plaintext message
def pad(plaintext, block_size):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


# Simulated CBC encryption function
def cbc_encrypt(plaintext, key, iv, block_size):
    """Encrypt using CBC mode."""
    # Get the hash code (HMAC) of the raw plaintext data
    hash_value = hmac.new(key, plaintext, hashlib.sha256).digest()
    print("HMAC:", hash_value, "-", len(hash_value), "bits")

    # Appends the HMAC to the raw plaintext data
    combined_plaintext = plaintext + hash_value
    print("plaintext:", combined_plaintext)

    # Pad the plaintext message
    padded_plaintext = pad(combined_plaintext, block_size)
    print("padded_plaintext:", padded_plaintext)

    previous = iv
    ciphertext = b""

    # Iterate over the ciphertext in blocks
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i : i + block_size]
        cipher_block = xor_bytes(previous, block)  # Encrypt using XOR
        ciphertext += cipher_block
        previous = cipher_block

    return ciphertext


st.title("Account Registration Page")
st.text("First time user? Sign up for an account today!")

# Create a textbox for client to enter new account credentials
username_input = st.text_input("Username:")
password_input = st.text_input("Password:", type="password")

# Create a button to send the account credentials to the server browser
if st.button("Register"):
    secret_username = username_input.encode("utf-8")
    secret_password = password_input.encode("utf-8")

    # Generate keys for username
    iv_username = os.urandom(block_size)
    key_username = os.urandom(key_size)
    print("username key:", key_username)
    key_username_int = int.from_bytes(key_username, byteorder="big")
    print(key_username_int.bit_length(), "bits")

    # Generate keys for password
    iv_password = os.urandom(block_size)
    key_password = os.urandom(key_size)
    print("password key:", key_password)
    key_password_int = int.from_bytes(key_password, byteorder="big")
    print(key_password_int.bit_length(), "bits")

    # Perform CBC encryption on plaintext username input
    print("Encrypt username:")
    try:
        ciphertext_username = cbc_encrypt(
            secret_username, 
            key_username, 
            iv_username, 
            block_size
        )
    except Exception as e:
        st.error(f"Error in decryption: {e}")

    # Store the username field in session states
    st.session_state["ciphertext_username"] = ciphertext_username
    st.session_state["iv_username"] = iv_username
    st.session_state["key_username"] = key_username

    # Perform CBC encryption on plaintext password input
    print("Encrypt password:")
    try:
        ciphertext_password = cbc_encrypt(
            secret_password, 
            key_password, 
            iv_password, 
            block_size
        )
    except Exception as e:
        st.error(f"Error in decryption: {e}")

    # Store the password field in session states
    st.session_state["ciphertext_password"] = ciphertext_password
    st.session_state["iv_password"] = iv_password
    st.session_state["key_password"] = key_password

    # Display account registration status
    st.success("Account registered successfully!")
    st.markdown(
    f"""
        Please confirm that your password is: `{secret_password.decode('utf-8')}`

        \nYour username is: `{ciphertext_username.hex()}`  
        Your password is: `{ciphertext_password.hex()}`
    """
    )
