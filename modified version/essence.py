import os
import random


# To simulate encryption process
# a and b parameters are byte string b'\x01\x02\x03'
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


# Padding. Self descriptive. If left 3 bytes, it will add 0x03 to convey it pads 3 times.
# return b"HELLO" + bytes([3] * 3)
# return b"HELLO" + b'\x03\x03\x03'
def pad(plaintext, block_size=8):
    """Apply PKCS#7 padding."""
    padding_len = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_len] * padding_len)


# Unpadding. Check how many bytes indicated by the self descriptive message, then remove the number of bytes, which are the padding
def unpad(padded_text):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]
    if padding_len == 0 or padding_len > len(padded_text):
        raise ValueError("Invalid padding")
    if all(p == padding_len for p in padded_text[-padding_len:]):
        return padded_text[:-padding_len]
    else:
        raise ValueError("Invalid padding")


# Simple CBC encryption and decryption functions
# iv is the previosu block's ciphertext. For first block, it will be the real 'iv'
# iv will xor with the padded plain text byte-by-byte
def cbc_encrypt(plaintext, key, iv, block_size=8):
    """Encrypt using CBC mode."""
    plaintext = pad(plaintext, block_size)
    blocks = [
        iv
    ]  # initialize the list blocks with the iv inside. E.g. [0x12 0x34 0x56 0x78 0xAB 0xCD 0xEF 0x00]
    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        cipher_block = xor_bytes(blocks[-1], block)  # Simulated "encryption" using XOR
        blocks.append(
            cipher_block
        )  # blocks.append(cipher_block) → blocks = [iv, cipher_block].
        ciphertext += cipher_block
    return ciphertext


def cbc_decrypt(ciphertext, key, iv, block_size=8):
    """Decrypt using CBC mode."""
    blocks = [iv] + [
        ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)
    ]
    plaintext = b""
    for i in range(1, len(blocks)):
        decrypted_block = xor_bytes(
            blocks[i], blocks[i - 1]
        )  # Simulated "decryption" using XOR
        plaintext += decrypted_block
    return unpad(plaintext)


# Initialize parameters
block_size = 8
key = os.urandom(block_size)  # Random key
iv = os.urandom(block_size)  # Initialization vector
secret_message = b"ATTACKATDAWN"  # Secret message to decrypt

# Encrypt the message
ciphertext = cbc_encrypt(secret_message, key, iv, block_size)
print("Ciphertext:", ciphertext.hex())


def server_check_padding(modified_block, target_block, block_size):
    """Simulate server-side padding check."""
    decrypted_byte = xor_bytes(modified_block, target_block)
    padding_value = decrypted_byte[-1]

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


# Run the simulated attack
try:
    decrypted_message = poodle_attack(ciphertext, iv, block_size)
    print("Decrypted Message:", decrypted_message.decode())
except ValueError as e:
    print("Decryption failed:", e)
