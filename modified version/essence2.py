import os
import random


def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def pad(plaintext, block_size=8):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding")
    if all(p == padding_len for p in padded_text[-padding_len:]):
        return padded_text[:-padding_len]
    else:
        raise ValueError("Invalid padding")


def cbc_encrypt(plaintext, key, iv, block_size=8):
    """Encrypt using CBC mode."""
    plaintext = pad(plaintext, block_size)
    blocks = [iv]
    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        cipher_block = xor_bytes(blocks[-1], block)
        blocks.append(cipher_block)
        ciphertext += cipher_block
    return ciphertext


def cbc_decrypt(ciphertext, key, iv, block_size=8):
    """Decrypt using CBC mode."""
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]
    plaintext = b""
    for i in range(1, len(blocks)):
        decrypted_block = xor_bytes(blocks[i], blocks[i - 1])
        plaintext += decrypted_block
    return unpad(plaintext)


# Separated server-side padding validation
class PaddingOracle:
    def __init__(self, key, iv, block_size=8):
        self.key = key
        self.iv = iv
        self.block_size = block_size

    def check_padding(self, ciphertext):
        """
        Server-side padding validation.
        Returns True if padding is valid, False if invalid.
        This simulates what a real server would do when receiving encrypted data.
        """
        try:
            # Attempt to decrypt and validate padding
            blocks = [self.iv] + [
                ciphertext[i : i + self.block_size]
                for i in range(0, len(ciphertext), self.block_size)
            ]
            plaintext = b""
            for i in range(1, len(blocks)):
                decrypted_block = xor_bytes(blocks[i], blocks[i - 1])
                plaintext += decrypted_block

            # Check padding validity
            padding_len = plaintext[-1]
            if padding_len == 0 or padding_len > self.block_size:
                return False
            if not all(p == padding_len for p in plaintext[-padding_len:]):
                return False
            return True

        except Exception:
            return False


def poodle_attack(ciphertext, iv, oracle, block_size=8):
    """
    Perform POODLE attack using a padding oracle.
    Now uses an external oracle to check padding validity instead of doing it internally.
    """
    decrypted_message = b""
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]

    for block_index in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        target_block = blocks[block_index]
        previous_block = bytearray(blocks[block_index - 1])

        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            found = False

            for guess in range(256):
                modified_block = previous_block[:]
                modified_block[byte_index] = guess

                # Apply padding values to other bytes
                for i in range(byte_index + 1, block_size):
                    modified_block[i] = (
                        previous_block[i] ^ padding_value ^ decrypted_block[i]
                    )

                # Create test ciphertext with modified block
                test_ciphertext = bytes(modified_block) + target_block

                # Check padding with the oracle
                if oracle.check_padding(test_ciphertext):
                    decrypted_block[byte_index] = (
                        guess ^ padding_value ^ previous_block[byte_index]
                    )
                    found = True
                    break

            if not found:
                raise ValueError(f"Unable to determine padding for byte {byte_index}")

        decrypted_message += bytes(decrypted_block)

    return unpad(decrypted_message)


# Example usage
if __name__ == "__main__":
    # Initialize parameters
    block_size = 8
    key = os.urandom(block_size)
    iv = os.urandom(block_size)
    secret_message = b"ATTACKATDAWN"

    # Create oracle and encrypt message
    oracle = PaddingOracle(key, iv, block_size)
    ciphertext = cbc_encrypt(secret_message, key, iv, block_size)
    print("Ciphertext:", ciphertext.hex())

    # Run the attack
    try:
        decrypted_message = poodle_attack(ciphertext, iv, oracle, block_size)
        print("Decrypted Message:", decrypted_message.decode())
    except ValueError as e:
        print("Decryption failed:", e)
