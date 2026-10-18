import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
import zipfile

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

URL = "http://gw.amnezia.org/v1/account_info"
PEM = re.compile(rb"-----BEGIN PUBLIC KEY-----.{100,4000}?-----END PUBLIC KEY-----", re.S)


def candidates(apk):
    found = []
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if name.endswith(".so"):
                for match in PEM.finditer(archive.read(name)):
                    pem = match.group().replace(b"\n", b"\n").decode("ascii").strip() + "\n"
                    if pem not in found:
                        found.append(pem)
    return found


def aes(key, iv):
    return Cipher(algorithms.AES(key), modes.CBC(iv[:16]))


def accepted(pem):
    """The server decrypts a request only with its current key and then answers encrypted."""
    key, iv = os.urandom(32), os.urandom(32)
    secret = json.dumps({"aes_key": base64.b64encode(key).decode(), "aes_iv": base64.b64encode(iv).decode(),
                         "aes_salt": base64.b64encode(os.urandom(8)).decode()}).encode()
    rsa = serialization.load_pem_public_key(pem.encode())
    padder = padding.PKCS7(128).padder()
    plain = padder.update(json.dumps({"installation_uuid": str(uuid.uuid4())}).encode()) + padder.finalize()
    encryptor = aes(key, iv).encryptor()
    body = json.dumps({"key_payload": base64.b64encode(rsa.encrypt(secret, PKCS1v15())).decode(),
                       "api_payload": base64.b64encode(encryptor.update(plain) + encryptor.finalize()).decode()})
    request = urllib.request.Request(URL, body.encode(), {"Content-Type": "application/json",
                                                          "X-Client-Request-ID": str(uuid.uuid4())})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            reply = response.read()
    except urllib.error.HTTPError as exc:
        reply = exc.read()
    if not reply or len(reply) % 16:
        return False
    decryptor = aes(key, iv).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        text = unpadder.update(decryptor.update(reply) + decryptor.finalize()) + unpadder.finalize()
        return "http_status" in json.loads(text)
    except ValueError:
        return False


def main(apk, out):
    working = [pem for pem in candidates(apk) if accepted(pem)]
    if len(working) != 1:
        sys.exit(f"expected one working key, got {len(working)}")
    with open(out, "w", newline="\n") as fh:
        fh.write(working[0])


if __name__ == "__main__":
    main(*sys.argv[1:3])
