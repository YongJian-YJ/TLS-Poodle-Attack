import streamlit as st
import base64
import os
import hmac
import hashlib

block_size = 16


# Function to simulate XOR operation between two byte-like objects
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# # Function to unpad the decrypted message (reverse of padding)
# def unpad(padded_text):
#     """Remove PKCS#7 padding."""
#     padding_len = padded_text[-1]
#     if padding_len == 0 or padding_len > len(padded_text):
#         raise ValueError("Invalid padding")
#     if all(p == padding_len for p in padded_text[-padding_len:]):
#         return padded_text[:-padding_len]
#     else:
#         raise ValueError("Invalid padding")


# # CBC decryption function
# def cbc_decrypt(ciphertext, key, iv, block_size):
#     """Decrypt using CBC mode."""
#     blocks = [iv]  # Initialize blocks with IV
#     decrypted_message = b""

#     # Iterate over the ciphertext in blocks
#     for i in range(0, len(ciphertext), block_size):
#         block = ciphertext[i : i + block_size]
#         decrypted_block = xor_bytes(block, blocks[-1])  # Decrypt using XOR
#         decrypted_message += decrypted_block
#         blocks.append(
#             block
#         )  # Add the current block to the list of blocks for XOR with next block

#     # Unpad the decrypted message
#     return unpad(decrypted_message)


# Function to unpad the decrypted message (reverse of padding)
def unpad(padded_text, key, hmac_len=32):
    """Remove PKCS#7 padding."""
    # # Number of bits that have been padded is stored as the padded bit
    # padding_bits = ord(text[-1:]) + 1
    # # Extracting the message
    # msg = text[0:len(text) - 32 - padding_bits]
    # # Hash of the authentication code
    # hash_rec = text[len(msg):-padding_bits]
    # hash_ver = hmac.new(KEY, msg, hashlib.sha256).digest()
    # if hash_rec != hash_ver :
    # # Checking if the hash derived from the cipher is the same as calculate from message
    #     if debug:
    #         print("corrupted data...")
    #         print('hash received : ', hash_rec)
    #         print('hash computed : ', hash_ver)
    #     msg = "1"
    # return msg

    # raw_plaintext + hmac + padding
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding!")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding!")
    else:
        raw_plaintext = padded_text[0:len(padded_text) - hmac_len - padding_len]
        hash_value = padded_text[len(raw_plaintext):-padding_len]
        original_hash = hmac.new(key, raw_plaintext, hashlib.sha256).digest()

        if hash_value == original_hash:
            print("HMAC valid!")
            return raw_plaintext
        else:
            print("hash received:", hash_value)
            print("original hash:", original_hash)
            return "HMAC invalid!"


# CBC decryption function
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

    
    # Unpad the decrypted message
    return unpad(decrypted_message, key)


# Set the title for the page
st.title("Server Page")

# Create a placeholder to display the message
message_placeholder = st.empty()

# Create a "Refresh" button
if st.button("Registration Logs"):
    if (
        "ciphertext_username" in st.session_state
        and "iv_username" in st.session_state
        and "ciphertext_password" in st.session_state
        and "iv_password" in st.session_state
    ):
        # Decode the username field
        ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        try:
            # Perform CBC decryption on ciphered username input
            decrypted_username = cbc_decrypt(
                ciphertext_username, 
                key_username, 
                iv_username, 
                block_size
            )
        except Exception as e:
            message_placeholder.write(f"Error in decryption: {e}")

        # Decode the password field
        ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        try:
            # Perform CBC decryption on ciphered password input
            decrypted_password = cbc_decrypt(
                ciphertext_password, 
                key_password, 
                iv_password, 
                block_size
            )

        except Exception as e:
            message_placeholder.write(f"Error in decryption: {e}")

        if (decrypted_username != "HMAC invalid!") and (decrypted_password != "HMAC invalid!"):
            st.markdown(
                f"""
                Username: `{decrypted_username.decode('utf-8')}`  
                Password: `{decrypted_password.decode('utf-8')}`
                """
            )
        else:
            message_placeholder.write("HMAC invalid!")
    else:
        message_placeholder.write("No message received yet.")
