#!/bin/python

import requests
import Crypto.PublicKey.RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS, PKCS1_v1_5
import OpenSSL
from OpenSSL import crypto
import md5
import base64
import json
import hashlib
import sys
import binascii
from hexdump import hexdump

CA="https://acme-staging.api.letsencrypt.org"
key_filename = 'account_staging.key'
nonce = False

def gen_protected():
    global nonce
    if not nonce:
        r = requests.get("{}/directory".format(CA))
        nonce = r.headers['Replay-Nonce']
    
    protected = { "nonce" : nonce }
    return protected

def load_key(filename):
    with open(filename, 'r') as myfile:
            account_key=myfile.read()
    return account_key

def _b64(string):
    return base64.urlsafe_b64encode(string).replace(b'=', b'')

def encode_dict(dictionary):
    return _b64(json.dumps(dictionary))

def gen_signature(key, payload, protected):
    message =  "{}.{}".format(encode_dict(protected),encode_dict(payload))
    key = load_key(key_filename)
    if key.startswith('-----BEGIN '):
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
    else:
        pkey = crypto.load_pkcs12(key).get_privatekey()
    print pkey
    sign = OpenSSL.crypto.sign(pkey, message, "sha256") 
    return _b64(sign)

def send_req(endpoint, payload):
    # example of request
    raw_key = load_key(key_filename)
    key = Crypto.PublicKey.RSA.importKey(raw_key)

    modulus = key.n
    public_exponent = key.e

    modulus = hex(modulus).split("x")[1][:-1]
    binary_string = binascii.unhexlify(modulus)

    request_jwks = {"alg":"RS256","jwk": {
        "e": 'AQAB',
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(binary_string).replace(b'=',b'')
        }}
    protected = gen_protected()
    signature = gen_signature(key, payload, protected)
    data={"header": request_jwks ,
            "protected":encode_dict(protected),
            "payload":encode_dict(payload),
            "signature":signature}
    r = requests.post("{}{}".format(CA, endpoint), json.dumps(data))
    return r.json()

domains = ['test.com', 'example.org']
payload = {"resource":"new-authz","identifier": {"type":"dns","value":domains[0]}}
send_req('/acme/new-authz',payload)

print "DONE"
