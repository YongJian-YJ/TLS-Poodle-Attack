import streamlit as st
import os

st.title("Eve's Control Page")


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    print(
        f"Padding length: {padding_len}, Padded message: {padded_text}"
    )  # Debugging line

    if padding_len == 0 or padding_len > len(padded_text):
        print("Invalid Padding 3")
        raise ValueError("Invalid padding3")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
        print("Invalid Padding 4")
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
    """Perform a POODLE-like attack by decrypting the last byte of each block."""
    decrypted_message = b""
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    for block_index in range(len(blocks) - 1, 0, -1):
        print("blocks index:", blocks[block_index].hex())
        decrypted_block = bytearray(block_size)
        target_block = blocks[block_index]
        previous_block = bytearray(blocks[block_index - 1])

        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            found = False
            for guess in range(256):
                modified_block = previous_block[:]
                modified_block[byte_index] = guess
                # to get corresponding value for byte that have been calculated
                for i in range(byte_index + 1, block_size):
                    modified_block[i] = (
                        previous_block[i] ^ padding_value ^ decrypted_block[i]
                    )

                try:
                    server_check = server_check_padding(
                        modified_block, target_block, block_size, padding_value
                    )

                    if server_check == True:
                        # Calculate the original byte value in the plaintext
                        decrypted_block[byte_index] = (
                            guess ^ padding_value ^ previous_block[byte_index]
                        )
                        st.write(
                            "Block No: ",
                            block_index,
                            ". Decrypted byte: ",
                            byte_index,
                            " . Value is ",
                            chr(decrypted_block[byte_index]),
                        )
                        found = True
                        break
                except ValueError:
                    continue

            if not found:
                raise ValueError("Unable to determine padding")

        decrypted_message += bytes(decrypted_block)
    print("Decrypted Message: "decrypted_message)
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
