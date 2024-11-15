import streamlit as st
import base64

# Set the title for the page
st.title("Server Page")


def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding")
    if all(p == padding_len for p in padded_text[-padding_len:]):
        return padded_text[:-padding_len]
    else:
        raise ValueError("Invalid padding")


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


# Create a placeholder to display the message
message_placeholder = st.empty()

# Create a "Refresh" button
if st.button("Refresh"):
    message = base64.b64decode(st.session_state["ciphertext"])
    iv = base64.b64decode(st.session_state["iv"])  # Decode IV from base64

    # decrypt the message
    decrypted_message = poodle_attack(message, iv, 8).decode()
    print("decrypted_message: ", decrypted_message)

    # Display the message from session state when the button is pressed
    if "message" in st.session_state and st.session_state["ciphertext"]:
        message_placeholder.write(f"Message from Alice: {decrypted_message}")
    else:
        message_placeholder.write("No message received yet.")
