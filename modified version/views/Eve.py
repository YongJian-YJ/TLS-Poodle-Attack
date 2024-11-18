import streamlit as st
import os

st.title("Eve's Control Page")


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding")
    return padded_text[:-padding_len]


def server_check_padding(modified_block, target_block, block_size, padding_value):
    """Simulate server-side padding check."""
    decrypted_byte = xor_bytes(modified_block, target_block)

    # Validate padding
    if padding_value == 0 or padding_value > block_size:
        raise ValueError("Invalid padding")
    if all(p == padding_value for p in decrypted_byte[-padding_value:]):
        return True
    else:
        raise ValueError("Invalid padding")


# Simulate POODLE Attack: Byte-by-byte decryption
def poodle_attack(ciphertext, iv, block_size=8):
    """Perform a POODLE-like attack by decrypting the last byte of each block."""
    decrypted_message = b""
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    # Start from last ciphertext block
    for block_index in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        target_block = blocks[block_index]
        previous_block = bytearray(blocks[block_index - 1])

        # Decrypt byte-by-byte
        for byte_index in range(block_size - 1, -1, -1):  # From last byte to first byte
            #  if the block size is 16 and the plaintext length is 13, (16 - 13 = 3)
            padding_value = block_size - byte_index
            found = False  # Flag to mark when correct byte is found
            for guess in range(256):  # 256 because 2^8 is 256 possibilities
                # creates a copy of the previous_block list.
                # brute force the modified_block, byte-by-byte
                modified_block = previous_block[:]
                modified_block[byte_index] = guess

                # Apply padding values to other bytes
                for i in range(byte_index + 1, block_size):
                    modified_block[i] = (
                        previous_block[i] ^ padding_value ^ decrypted_block[i]
                    )

                try:
                    # Attempt decryption with the modified block
                    # Modified block is the previous block, attacker manipulate this using trial and error
                    # Target block is the current ciphertext block that the attacker is trying to decrypt
                    # Padding validation processes depend on the entire P, not just one byte.
                    server_check = server_check_padding(
                        modified_block, target_block, block_size, padding_value
                    )

                    # if padding value = 3 and the [padding value] = [3], so the product become [3, 3, 3] and byte(xx) become b'\x03\x03\x03'
                    # Vulnerability: Attacker know that the padding will be the same value for each padding byte and will be equal to the number of padding bytes.
                    if server_check == True:
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


# Create interface for attack
st.subheader("Intercepted Message")

if st.button("Intercept Message"):
    if "ciphertext" in st.session_state and "iv" in st.session_state:
        intercepted_ciphertext = st.session_state["ciphertext"]
        iv = st.session_state["iv"]
        key = st.session_state["key"]
        block_size = 8

        st.write("Intercepted ciphertext (hex):", intercepted_ciphertext.hex())
        st.write("IV (hex):", iv.hex())

        try:
            decrypted = poodle_attack(intercepted_ciphertext, iv, block_size)

            st.success(f"Decrypted message: {decrypted.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack failed: {str(e)}")
    else:
        st.error("No message has been intercepted yet!")
