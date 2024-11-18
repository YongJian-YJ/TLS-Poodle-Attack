import streamlit as st
import os

st.title("Eve's Control Page")
block_size = 8


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


class PaddingOracle:
    def __init__(self, key, iv, block_size=8):
        self.key = key
        self.iv = iv
        self.block_size = block_size

    def decrypt_block(self, prev_block, curr_block):
        """Decrypt a single block."""
        return xor_bytes(prev_block, curr_block)

    def check_padding(self, ciphertext):
        """Check if the padding is valid for the given ciphertext."""
        try:
            blocks = [
                ciphertext[i : i + self.block_size]
                for i in range(0, len(ciphertext), self.block_size)
            ]

            # Use the stored IV as the first block
            prev_block = self.iv
            plaintext = b""

            # Decrypt each block
            for curr_block in blocks:
                decrypted = self.decrypt_block(prev_block, curr_block)
                plaintext += decrypted
                prev_block = curr_block

            # Validate padding
            padding_len = plaintext[-1]
            if padding_len == 0 or padding_len > self.block_size:
                return False
            return plaintext[-padding_len:] == bytes([padding_len] * padding_len)

        except Exception:
            return False


def poodle_attack(ciphertext, iv, oracle, block_size=8):
    """Perform POODLE attack to decrypt the message."""
    decrypted = b""
    blocks = [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    for block_idx in range(len(blocks)):
        current_block = bytearray(blocks[block_idx])
        if block_idx == 0:
            prev_block = bytearray(iv)
        else:
            prev_block = bytearray(blocks[block_idx - 1])

        decrypted_block = bytearray(block_size)

        # Try to decrypt each byte
        for byte_idx in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_idx

            for guess in range(256):
                # Modify the previous block
                test_prev = prev_block[:]
                test_prev[byte_idx] = guess

                # Set proper padding for known bytes
                for i in range(byte_idx + 1, block_size):
                    test_prev[i] ^= padding_value ^ decrypted_block[i]

                # Test if padding is valid
                test_cipher = bytes(test_prev) + bytes(current_block)
                if oracle.check_padding(test_cipher):
                    decrypted_block[byte_idx] = (
                        guess ^ padding_value ^ prev_block[byte_idx]
                    )
                    break
            else:
                raise ValueError(f"Could not find valid padding for byte {byte_idx}")

        decrypted += bytes(decrypted_block)

    return unpad(decrypted)


# Create interface for attack
st.subheader("Intercepted Message")

if st.button("Intercept Message"):
    if "ciphertext" in st.session_state and "iv" in st.session_state:
        intercepted_ciphertext = st.session_state["ciphertext"]
        iv = st.session_state["iv"]
        key = st.session_state["key"]

        st.write("Intercepted ciphertext (hex):", intercepted_ciphertext.hex())
        st.write("IV (hex):", iv.hex())

        try:
            # Create oracle with the same key and IV
            oracle = PaddingOracle(key, iv)

            # Perform POODLE attack
            decrypted = poodle_attack(intercepted_ciphertext, iv, oracle)

            st.success(f"Decrypted message: {decrypted.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack failed: {str(e)}")
    else:
        st.error("No message has been intercepted yet!")
