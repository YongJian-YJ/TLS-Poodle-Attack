"""
This is the server which contains the decryption algorithm.
It received encrypted text, decrypts them and sends a confirmation if
the cipher text was decrypted successfully and in case of a failure,
inform that it has failed.
"""

# For running the server
from flask import Flask, request
# For the implementation of AES code block and SHA authentication mechanism
from Crypto.Cipher import AES
import hmac, hashlib
# To remove the logging from the terminal.
import logging

server = Flask(__name__)

# Inititalization of the KEY and IV
KEY = None
IV = None


def unpad(text, debug=False):
    """
    The function unpads the padded cipher after decryption to extract the hash
    of the authentication code and the actual value of the message.
    """
    global KEY
    # Number of bits that have been padded is stored as the padded bit
    padding_bits = ord(text[-1:]) + 1
    # Extracting the message
    msg = text[0:len(text) - 32 - padding_bits]
    # Hash of the authentication code
    hash_rec = text[len(msg):-padding_bits]
    hash_ver = hmac.new(KEY, msg, hashlib.sha256).digest()
    if hash_rec != hash_ver :
    # Checking if the hash derived from the cipher is the same as calculate from message
        if debug:
            print("corrupted data...")
            print('hash received : ', hash_rec)
            print('hash computed : ', hash_ver)
        msg = "1"
    return msg


def decrypt(cipher):
    """
    The cipher text is decrypted using the KEY and IV using the AES code book.
    """
    global KEY
    global IV
    # This build the AES codebook
    aes_block = AES.new(KEY, AES.MODE_CBC, IV)
    # unpads the cipher after decryption
    plaintext = unpad(aes_block.decrypt(cipher))
    if plaintext != "1":
        print('deciphered message : ', plaintext)
    if plaintext == "1":
        return "1"
    else:
        return "0"

######### Flask Server #########
@server.route("/")
def base():
    return "<p>This is the back server!</p>"


@server.route("/key_iv")
def get_key():
    # This url is used for exchanging the key. In an ideal situation, this would have been done using an assymetric key exchange.
    # In this we however, openly transfer the KEY and IV
    # This is the function which is used for the key exchange.
    global KEY
    global IV
    # Deriving the key and IV from the request
    KEY = request.args.get('key')
    IV = request.args.get('iv')
    # Converting the key and IV into byte array for using it into AES
    KEY = bytearray.fromhex(KEY)
    IV = bytearray.fromhex(IV)
    return "0"


@server.route("/get_message")
def get_message():
    # This url is to get the message and decrypt it.
    # In the above function used (decrypt),
    # it also checks if its a valid cipher or not depending on the hash code.
    # 1 -> Invalid, 0 -> Valid
    msg = request.args.get('msg')
    msg = bytearray.fromhex(msg)
    msg = decrypt(msg)
    return msg


if __name__ == '__main__':
    print('Initialising server')
    server.logger.disabled = True
    log = logging.getLogger('werkzeug')
    log.disabled = True
    server.run(port=8000)