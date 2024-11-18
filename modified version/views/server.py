import streamlit as st
import base64
import os

block_size = 8


# Function to simulate XOR operation between two byte-like objects
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# Function to unpad the decrypted message (reverse of padding)
def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding")
    if all(p == padding_len for p in padded_text[-padding_len:]):
        return padded_text[:-padding_len]
    else:
        raise ValueError("Invalid padding")


# CBC decryption function
def cbc_decrypt(ciphertext, key, iv, block_size=8):
    """Decrypt using CBC mode."""
    blocks = [iv]  # Initialize blocks with IV
    decrypted_message = b""

    # Iterate over the ciphertext in blocks
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_block = xor_bytes(block, blocks[-1])  # Decrypt using XOR
        decrypted_message += decrypted_block
        blocks.append(
            block
        )  # Add the current block to the list of blocks for XOR with next block

    # Unpad the decrypted message
    return unpad(decrypted_message)


# Set the title for the page
st.title("Server Page")

# Create a placeholder to display the message
message_placeholder = st.empty()

# Create a "Refresh" button
if st.button("Refresh"):
    if "ciphertext" in st.session_state and "iv" in st.session_state:
        # Decode the ciphertext and IV from base64
        ciphertext = st.session_state["ciphertext"]
        iv = st.session_state["iv"]
        key = st.session_state["key"]

        try:
            # Perform CBC decryption
            decrypted_message = cbc_decrypt(ciphertext, key, iv, block_size)
            message_placeholder.write(
                f"Decrypted Message: {decrypted_message.decode('utf-8')}"
            )
        except Exception as e:
            message_placeholder.write(f"Error in decryption: {e}")
    else:
        message_placeholder.write("No message received yet.")
