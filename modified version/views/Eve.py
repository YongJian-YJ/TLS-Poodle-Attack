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
        raise ValueError("Invalid padding3")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding4")
    return padded_text[:-padding_len]


def server_check_padding(modified_block, target_block, block_size, padding_value):
    """Simulate server-side padding check."""
    decrypted_byte = xor_bytes(modified_block, target_block)

    if padding_value == 0 or padding_value > block_size:
        raise ValueError("Invalid padding1")
    if all(p == padding_value for p in decrypted_byte[-padding_value:]):
        return True
    else:
        raise ValueError("Invalid padding2")


def poodle_attack(ciphertext, iv, block_size=8):
    decrypted_message = bytearray()

    # Split into blocks, including IV
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    # Start from the last block and work backwards
    # Range from (len(blocks)-1) down to 1 (excluding 0 since we don't decrypt IV)
    for block_index in range(len(blocks) - 1, 0, -1):

        decrypted_block = bytearray(block_size)
        plaintext_block = bytearray(block_size)
        target_block = blocks[block_index]
        previous_block = bytearray(blocks[block_index - 1])

        # Process each byte in the block from right to left
        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            found = False

            # Try all possible byte values
            for guess in range(256):
                modified_block = previous_block[:]
                modified_block[byte_index] = guess

                # Update bytes that we've already found to maintain valid padding
                for i in range(byte_index + 1, block_size):
                    # D8 = C8 xor padding
                    decrypted_block[i] = previous_block[i] ^ padding_value

                    # C8 = D8 xor P8
                    modified_block[i] = decrypted_block[i] ^ plaintext_block[i]

                try:
                    server_check = server_check_padding(
                        modified_block, target_block, block_size, padding_value
                    )

                    if server_check:
                        # D8 xor C8 = 0x01
                        # D8 = C8 ^ 0x01
                        decrypted_block[byte_index] = guess ^ padding_value

                        # P8 ^ original C8 = D8
                        # P8 = D8 ^ original C8
                        plaintext_block[byte_index] = (
                            decrypted_block[byte_index] ^ previous_block[byte_index]
                        )

                        st.write(
                            "Block No: ",
                            block_index,
                            ". Decrypted byte: ",
                            byte_index,
                            " . Value is ",
                            chr(plaintext_block[byte_index]),
                        )
                        found = True
                        break

                except ValueError:
                    continue

            if not found:
                raise ValueError(
                    f"Failed to decrypt byte {byte_index} in block {block_index}"
                )

        # Insert the decrypted block at the beginning of our message
        # This maintains correct order since we're decrypting from end to start
        decrypted_message[0:0] = plaintext_block

    return unpad(decrypted_message)


# Create interface for attack
st.subheader("Intercepted Message")

if st.button("Intercept Message"):
    if (
        "ciphertext_username" in st.session_state
        and "iv_username" in st.session_state
        and "ciphertext_password" in st.session_state
        and "iv_password" in st.session_state
    ):
        block_size = 8
        # for username
        intercepted_ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        # for password
        intercepted_ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        st.write("Intercepted username:", intercepted_ciphertext_username)
        st.write("Intercepted IV for username:", iv_username.hex())

        st.write("Intercepted password:", intercepted_ciphertext_password)
        st.write("Intercepted IV for password:", iv_password.hex())

    else:
        st.error("Incomplete information required for poodle attack")

if st.button("Launch Poodle Attack"):
    if (
        "ciphertext_username" in st.session_state
        and "iv_username" in st.session_state
        and "ciphertext_password" in st.session_state
        and "iv_password" in st.session_state
    ):

        block_size = 8

        # Poodle for username
        intercepted_ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        try:
            decrypted = poodle_attack(
                intercepted_ciphertext_username, iv_username, block_size
            )

            st.success(f"Decrypted username: {decrypted.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack on username failed: {str(e)}")

        # Poodle for password
        intercepted_ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        try:
            decrypted = poodle_attack(
                intercepted_ciphertext_password, iv_password, block_size
            )

            st.success(f"Decrypted password: {decrypted.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack on password failed: {str(e)}")
    else:
        st.error("No message has been intercepted yet!")
