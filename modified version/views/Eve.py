import streamlit as st
import base64
import os

block_size = 8

# Set the title for Eve's control page
st.title("Eve's Control Page")

# Create a section to display the message from Alice
st.subheader("Message from Alice:")

# Option to simulate interception (could alter or log message)
if st.button("Intercept Message"):
    # Simulate intercepting the message, for example by logging or modifying it
    intercepted_message = base64.b64decode(st.session_state["ciphertext"])
    st.session_state["intercepted_message"] = intercepted_message
    st.success(f"Intercepted Message: {intercepted_message}")


def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding")
    if all(p == padding_len for p in padded_text[-padding_len:]):
        return padded_text[:-padding_len]
    else:
        raise ValueError("Invalid padding")


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


def pad(plaintext, block_size=8):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# Simulate POODLE Attack: Byte-by-byte decryption
def poodle_attack(ciphertext, iv, block_size=8):
    """Perform a POODLE-like attack by decrypting the last byte of each block."""
    decrypted_message = b""
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    # Start from first ciphertext block #it doesnt start from 0 because block 0 is IV
    for block_index in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        target_block = blocks[block_index]
        previous_block = bytearray(blocks[block_index - 1])

        # Decrypt byte-by-byte
        for byte_index in range(block_size - 1, -1, -1):  # From last byte to first byte
            padding_value = (
                block_size - byte_index
            )  #  if the block size is 16 and the plaintext length is 13, (16 - 13 = 3)
            found = False  # Flag to mark when correct byte is found
            for guess in range(256):  # 256 because 2^8 is 256 possibilities
                # creates a copy of the previous_block list.
                modified_block = previous_block[:]
                modified_block[byte_index] = guess  # Modify this byte

                # Apply padding values to other bytes
                for i in range(byte_index + 1, block_size):
                    modified_block[i] = (
                        previous_block[i] ^ padding_value ^ decrypted_block[i]
                    )

                try:
                    # Attempt decryption with the modified block
                    # Modified block is the previous block, attacker manipulate this using trial and error
                    # Target block is the current ciphertext block that the attacker is trying to decrypt
                    decrypted_byte = xor_bytes(modified_block, target_block)

                    # if padding value = 3 and the [padding value] = [3], so the product become [3, 3, 3] and byte(xx) become b'\x03\x03\x03'
                    # Vulnerability: Attacker know that the padding will be the same value for each padding byte and will be equal to the number of padding bytes.
                    if decrypted_byte[-padding_value:] == bytes(
                        [padding_value] * padding_value
                    ):
                        # Calculate the original byte value in the plaintext
                        decrypted_block[byte_index] = (
                            guess ^ padding_value ^ previous_block[byte_index]
                        )
                        found = True  # if true, break the guess loop and go to another byte_index
                        break  # Exit after finding correct padding
                except ValueError:
                    continue  # Skip invalid padding

            if not found:
                raise ValueError("Unable to determine padding")

        decrypted_message += bytes(decrypted_block)
    return unpad(decrypted_message)


# Display a log of intercepted messages (if relevant)
if "intercepted_message" in st.session_state:
    intercepted_message = base64.b64decode(st.session_state["ciphertext"])
    print("cyphertext: ", intercepted_message)
    iv = base64.b64decode(st.session_state["iv"])  # Decode IV from base64
    print("iv: ", iv)

    st.subheader("Poodle Attack")

    try:
        # Attempt to decrypt using POODLE attack
        plaintext = poodle_attack(intercepted_message, iv, 8)
        st.write("Decrypted Message: ", plaintext.decode())
    except Exception as e:
        st.error(f"Error in decryption: {e}")


# # Optional: Eve can modify the intercepted message before sending it forward
# if "intercepted_message" in st.session_state:
#     modified_message = st.text_input(
#         "Modify the message before sending:", plaintext.decode()
#     )
#     modified_message_to_send = b""
#     modified_message_to_send += modified_message_to_send

#     if st.button("Send Modified Message"):
#         # Base64 encode the modified message
#         key = os.urandom(block_size)
#         encrypted_message = cbc_encrypt(modified_message_to_send, key, iv)
#         st.session_state["ciphertext"] = base64.b64encode(encrypted_message).decode(
#             "utf-8"
#         )
#         st.success("Modified message sent to Server.")
