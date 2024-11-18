import streamlit as st
import os
import base64

block_size = 8

st.header("Alice's Control Page")

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
message_input = st.text_input("Enter your message:", value=st.session_state["message"])

# Create a button to send the message
if st.button("Send Message"):
    secret_message = message_input.encode("utf-8")

    # Generate IV for this message
    iv = os.urandom(block_size)
    key = st.session_state["key"]  # Use consistent key from session state

    # Store IV and key in session state
    st.session_state["iv"] = iv

    # Perform CBC encryption
    ciphertext = cbc_encrypt(secret_message, key, iv)

    # Store ciphertext in session state
    st.session_state["ciphertext"] = ciphertext

    # Display information
    st.write(f"Original Message: {message_input}")
    st.write(f"IV (hex): {iv.hex()}")
    st.write(f"Ciphertext (hex): {ciphertext.hex()}")

    st.success("Message encrypted and sent!")
