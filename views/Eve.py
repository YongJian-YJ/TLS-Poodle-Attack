import streamlit as st
import hmac, hashlib

# Follow ciphertext block size as per client Alice, according to Advanced Encryption Standard (AES).
block_size = 16

# Function to simulate decryption via XOR operation between two byte-like objects (for demo purposes only)
def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

# Function to unpad the decrypted message (reverse of padding)
def unpad(padded_text, key, hmac_len=32):
    """Remove PKCS#7 padding."""
    padding_len = padded_text[-1]

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
            print("Attacker: HMAC valid!")
            return raw_plaintext
        else:
            return "Attacker: HMAC invalid!"


# Oracle check function to validate padding in plaintext_block for poodle attack
def server_check_padding(modified_block, target_block, block_size, padding_value):
    # modified_block = C8's block
    # target_block = D8's block
    # plaintext_block = P8's block
    decrypted_byte = xor_bytes(modified_block, target_block)

    if isinstance(decrypted_byte, (bytes, bytearray)):
        decrypted_byte = list(decrypted_byte)

    # Extract out the padding bytes for Oracle check
    last_bytes = decrypted_byte[-padding_value:]
    # Valid padding: Padding value represents the number of padding bytes
    if last_bytes == [padding_value] * padding_value:
        return True
    else:
        raise ValueError("Oracle: Invalid padding!")


# Function to simulate POODLE attack on the SSL 3.0 connection between client (Alice) and server
def poodle_attack(ciphertext, iv, block_size, key):
    # modified_block = C8's block
    # target_block = D8's block
    # plaintext_block = P8's block
    # previous_block = IV
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
                    # E.g. D8 = C8 xor P8
                    decrypted_block[i] = previous_block[i] ^ padding_value

                    # E.g. C8 = D8 xor P8
                    modified_block[i] = decrypted_block[i] ^ plaintext_block[i]

                try:
                    # Oracle check function
                    server_check = server_check_padding(
                        modified_block, target_block, block_size, padding_value
                    )

                    if server_check == True:
                        # Example:
                        # D8 xor C8 = 0x01
                        # D8 = C8 xor 0x01
                        decrypted_block[byte_index] = (
                            modified_block[byte_index] ^ padding_value
                        )
                        
                        # Example:
                        # P8 xor original C8 = D8
                        # P8 = D8 xor original C8
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

    # Unpad the decrypted message and validate HMAC of original plaintext
    return unpad(bytes(decrypted_message), key)


# Create interface for attack
st.title("Eve's Control Page")
st.header("Intercepted Message")

if st.button("Intercept Message"):
    if (
        "ciphertext_username" and "iv_username" and 
        "ciphertext_password" and "iv_password"
    ) in st.session_state:
        # Extract the username field from session states
        intercepted_ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        # Extract the password field from session states
        intercepted_ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        # Display intercepted username
        st.write("Intercepted username:", intercepted_ciphertext_username)
        st.write("Intercepted IV for username:", iv_username.hex())

        # Display intercepted password
        st.write("Intercepted password:", intercepted_ciphertext_password)
        st.write("Intercepted IV for password:", iv_password.hex())

    else:
        st.error("Incomplete information required for poodle attack")

if st.button("Launch Poodle Attack"):
    if (
        "ciphertext_username" and "iv_username" and
        "ciphertext_password" and "iv_password"
    ) in st.session_state:
        # POODLE attack on username field
        intercepted_ciphertext_username = st.session_state["ciphertext_username"]
        iv_username = st.session_state["iv_username"]
        key_username = st.session_state["key_username"]

        try:
            print("Decrypted username:")
            decrypted_username = poodle_attack(
                intercepted_ciphertext_username, 
                iv_username, 
                block_size, 
                key_username
            )
            st.success(f"Decrypted username: {decrypted_username.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack on username failed: {str(e)}")

        # POODLE attack on password field
        intercepted_ciphertext_password = st.session_state["ciphertext_password"]
        iv_password = st.session_state["iv_password"]
        key_password = st.session_state["key_password"]

        try:
            print("Decrypted password:")
            decrypted_password = poodle_attack(
                intercepted_ciphertext_password, 
                iv_password, 
                block_size, 
                key_password
            )
            st.success(f"Decrypted password: {decrypted_password.decode('utf-8')}")
        except Exception as e:
            st.error(f"Attack on password failed: {str(e)}")
    else:
        st.error("No message has been intercepted yet!")
