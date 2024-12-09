import streamlit as st
import hmac, hashlib
from Crypto.Cipher import AES

# Follow ciphertext block size as per client Alice, according to Advanced Encryption Standard (AES).
block_size = AES.block_size

# Function to simulate decryption via XOR operation between two byte-like objects (for demo purposes only)
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

# Function to unpad the decrypted message (reverse of padding)
def unpad(padded_text, key):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    hmac_len = 32

    # Check for invalid padding first before unpadding
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding!")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding!")
    # Valid padding
    # raw_plaintext + hmac + padding
    else:
        raw_plaintext = padded_text[0:len(padded_text) - hmac_len - padding_len]
        hash_value = padded_text[len(raw_plaintext):-padding_len]
        print("hash received:", hash_value)
        original_hash = hmac.new(key, raw_plaintext, hashlib.sha256).digest()
        print("original hash:", original_hash)

        # Matching HMAC == Valid HMAC, and otherwise
        if hash_value == original_hash:
            print("Server: HMAC valid!")
            return raw_plaintext
        else:
            return "Server: HMAC invalid!"

# Simulated CBC decryption function
def cbc_decrypt(ciphertext, key, iv, block_size):
    """Decrypt using CBC mode."""
    blocks = [iv]  # Initialize blocks with IV
    decrypted_message = b""

    # Iterate over the ciphertext in blocks
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_block = xor_bytes(block, blocks[-1])  # Decrypt using XOR
        decrypted_message += decrypted_block
        blocks.append(block)  # Add the current block to the list of blocks for XOR with next block

    # Unpad the decrypted message and validate HMAC of original plaintext
    return unpad(decrypted_message, key)


st.title("Account Server Page")

# Create a "Refresh" button for server to receive user input
if st.button("Registration Logs"):
    # Check if session states contain the user input sent from Alice before performing decryption
    if (
        "ciphertext_username" and "iv_username" and "key_username" and
        "ciphertext_password" and "iv_password" and "key_password"
    ) in st.session_state:
        # Extract the username field from session states
        ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        try:
            # Perform CBC decryption on ciphered username input
            print("Decrypt username:")
            decrypted_username = cbc_decrypt(
                ciphertext_username, 
                key_username, 
                iv_username, 
                block_size
            )
        except Exception as e:
            st.error(f"Error in decryption: {e}")

        # Extract the password field from session states
        ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        try:
            # Perform CBC decryption on ciphered password input
            print("Decrypt password:")
            decrypted_password = cbc_decrypt(
                ciphertext_password, 
                key_password, 
                iv_password, 
                block_size
            )
        except Exception as e:
            st.error(f"Error in decryption: {e}")

        # Check if HMAC matches before decoding the decrypted username and password
        if (decrypted_username and decrypted_password) != "Server: HMAC invalid!":
            st.markdown(
                f"""
                Username: `{decrypted_username.decode('utf-8')}`  
                Password: `{decrypted_password.decode('utf-8')}`
                """
            )
            st.success("Account credentials received and decrypted!")
        else:
            st.error("HMAC is invalid!")
    else:
        st.error("No account credentials received yet.")