import streamlit as st
import os
from itertools import cycle
import base64

block_size = 8

# Header for Alice's control page
st.header("Alice's Control Page")

# Initialize the session state variable for the message if it doesn't exist
if "message" not in st.session_state:
    st.session_state["message"] = ""


# Function to simulate XOR operation between two byte-like objects
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# Function to pad the plaintext to the desired block size (8 bytes)
def pad(plaintext, block_size=8):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


# CBC encryption function
def cbc_encrypt(plaintext, key, iv, block_size=8):
    """Encrypt using CBC mode."""
    plaintext = pad(plaintext, block_size)
    blocks = [iv]  # initialize the list blocks with the iv inside
    ciphertext = b""

    # Iterate over the plaintext in blocks of size `block_size`
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        cipher_block = xor_bytes(blocks[-1], block)  # Simulated "encryption" using XOR
        blocks.append(cipher_block)  # Append the cipher block to blocks
        ciphertext += cipher_block

    return ciphertext


# Create a textbox for Alice to type the message
message_input = st.text_input("Enter your message:", value=st.session_state["message"])

# Create a button to send the message
if st.button("Send Message"):
    # Example key and IV for encryption (for simplicity, use fixed values)
    key = os.urandom(block_size)
    iv = os.urandom(block_size)
    st.write(f"IV: {iv}")
    st.session_state["iv"] = base64.b64encode(iv).decode("utf-8")

    # Perform CBC encryption
    ciphertext = cbc_encrypt(st.session_state["message"].encode(), key, iv)

    st.write(f"Original Message: {message_input}")
    st.write(f"Ciphertext (hex): {ciphertext.hex()}")
    st.write(f"Ciphertext (raw): {ciphertext}")

    # Save the message to the session state when the button is pressed
    st.session_state["ciphertext"] = base64.b64encode(ciphertext).decode("utf-8")
    st.success("Ciphertext sent!")
