"""
This is the client side.
The client does the following things:
# Generates the KEY and the IV and sends it to the server.
# Encrypts all plaintext image before sending it to the server.
# Accepts input from the attacker, appends it before and after the
secret message, encrypts it and sends to the server.
# Can make arbitrary number of requests to the server depending on
the requirement of the attacker.
"""


# Importing the http communication packages
from flask import Flask, request
import requests
# Importing cryptography library for hash and aes
from Crypto.Cipher import AES
from Crypto import Random # Random number generator
import hmac, hashlib
# For conversion
import binascii
import logging
import time


client = Flask(__name__)


# Initialization of KEY and IV
KEY = None
IV = None
MSG = None
# PORTS and URLS where the attacker and server resides
SERVER_PORT = 8000
ATTACKER_PORT = 8002

SERVER_URL = f'http://127.0.0.1:{SERVER_PORT}/'
ATTACKER_URL = f"http://127.0.0.1:{ATTACKER_PORT}/"


# Generates the random key and IV for the AES.
def generate_key():
    global KEY
    global IV
    KEY = Random.new().read(AES.block_size)
    IV = Random.new().read(AES.block_size)
    return

# Send the KEY and IV generated to the server.
def exchange_key():
    global KEY
    global IV
    global SERVER_URL
    r = requests.get(SERVER_URL+'key_iv', params={'key':KEY.hex(), 'iv' : IV.hex()})
    return

# Padding AES block
def pad(text):
    # Pads the text with the number of padding bits to ensure that the total length is a multiple of the block size (16 bytes)
    remaining_bytes = 16 - len(text) % 16
    pad = remaining_bytes * chr((16 - len(text) - 1) % 16)
    pad = pad.encode()
    return pad


def encrypt(raw_text):
    """
    Main encryption function which encrypts the raw data. It also
    performs the hash code for authentication and does the padding.
    """
    data = raw_text.encode()
    # Gets the has code
    hash_value = hmac.new(KEY, data, hashlib.sha256).digest()
    # Appends the hash code and the data
    plaintext = data + hash_value
    padding = pad(plaintext)
    plaintext = plaintext + padding
    # Produes the cipher text
    aes_block = AES.new(KEY, AES.MODE_CBC, IV)
    cipher = aes_block.encrypt(plaintext)
    return cipher


def send_message(cipher):
    """
    Sends the message to the server as well as the attacker.
    This simulates the case where the attacker listens to the communication.
    """
    r = requests.get(SERVER_URL+'get_message', params={'msg':cipher})
    a = requests.get(ATTACKER_URL+'intercept', params={'msg':cipher}).text
    print("original message returned:", a)
    return a


# def wait_for_decryption():
#     """
#     Simulates waiting for a response indicating that the message has been decrypted.
#     Replace this with actual communication with the attacker/server.
#     """
#     response = None
#     while response != MSG:
#         # Simulate checking for a response from the attacker or server.
#         # In an actual implementation, this would involve network communication or polling.
#         response = requests.get(ATTACKER_URL + 'decryption_status').text  # Replace with actual method to get response
#         # print(response)
#         if response == MSG:
#             return response
#         time.sleep(1)  # Wait to avoid busy-waiting
#     # print(response)
#     return response


def attacker(cipher):
    """
    This function is used to send the cipher text back to the attacker when
    he/she is trying to figure of the number of padded bytes.
    """
    a = requests.get(ATTACKER_URL+'pad_block', params={'msg':cipher}).text
    print("decrypted plaintext:", a)
    return a


def randkey():
    # Generates new random keys and IV
    global IV
    global KEY
    IV = Random.new().read( AES.block_size )
    KEY = Random.new().read( AES.block_size )


@client.route("/attack_pad_block")
def attacker_listen():
    """
    This url is for getting the deviation messsages from the attacker
    which needs to be sent to client.
    The padding is added before and after to get the new message.
    """
    global MSG
    pad_before = request.args.get('pad_before')
    pad_after = request.args.get('pad_after')
    if pad_after == "-1":
        pad_after = ""
    if pad_before == "-1":
        pad_before = ""
    # New message and cipher from AES
    msg = pad_before + MSG + pad_after
    cipher = encrypt(msg)
    print("length:",len(cipher))
    resp = attacker(binascii.hexlify(cipher))
    print("attack_pad_block:", resp)
    return resp


def send_poodle_attack(cipher):
    r = requests.get(SERVER_URL+'get_message', params={'msg':cipher})
    a = requests.get(ATTACKER_URL+'pad_block', params={'msg':cipher})
    return


@client.route("/poodle_attack")
def poodle_inititate():
    """
    This url is for the poodle attack initiation
    """
    a = requests.get(ATTACKER_URL+'poodle_attack').text
    print("poodle_attack:", a)
    return a


@client.route("/poodle_request")
def poodle_request():
    """
    Poodle attack url
    1. Key refresh and exchange
    2. Compute new cipher
    3. Send it to the attacker and server.
    """
    randkey()
    exchange_key()
    pad_before = request.args.get('pad_before')
    pad_after = request.args.get('pad_after')
    # Computing the new pad
    msg = pad_before + MSG + pad_after
    cipher = encrypt(msg) # Compute the encrypted messages
    return cipher.hex()


@client.route("/")
def base():
    """
    Base URL which inititates the converstation between the three parties.
    There is a manual need to explicitly go to this url to start the attack.
    """
    global MSG

    print('Initialising client')
    # Generate and exchange the keys
    generate_key()
    exchange_key()
    MSG = "Hello World!"
    # Encrypt and sends the message
    cipher = encrypt(MSG)
    result = send_message(cipher.hex())
    #  # Wait for decryption confirmation
    # decrypted_message = wait_for_decryption()
    
    # if decrypted_message == MSG:
    #     print("Message successfully decrypted by the attacker")
    #     return "<p>The attack has completed successfully!</p>"
    # else:
    #     print("Decryption failed or incomplete")
    #     return "<p>Decryption failed or incomplete.</p>"
    print("final result:", result)
    if result == MSG:
        return "<p>Your secret message has been eavesdropped by an attacker!</p><p>Secret message: " + MSG + " </p>"
    else:
        return "<p>The attack has failed.</p>"


if __name__ == '__main__':
    client.logger.disabled = True
    log = logging.getLogger('werkzeug')
    log.disabled = True
    client.run(port=8001)