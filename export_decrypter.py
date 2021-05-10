#!/usr/bin/python3

import argparse
import base64
import binascii

import boto3
import requests
import os

from Crypto.Cipher import AES
from Crypto.Util import Counter


def main():
    args = command_line_args()
    s3_client = client(args.localstack)
    s3_object = s3_client.get_object(Bucket=args.bucket, Key=args.path)
    object_metadata = s3_object['Metadata']
    encrypted_key = object_metadata['ciphertext']
    encrypting_key_id = object_metadata['datakeyencryptionkeyid']
    initialisation_vector = object_metadata['iv']
    decrypted_key = decrypted_datakey(args.dks_url, args.certificate, args.key, args.dks_certificate, encrypting_key_id,
                                      encrypted_key)
    contents = object_contents(s3_object)
    decrypted = decrypted_contents(decrypted_key, initialisation_vector, contents)
    filename = os.path.basename(args.path).replace(".enc", "")
    with open(filename, "wb") as f:
        f.write(decrypted)


def decrypted_contents(key: str, iv: str, ciphertext: bytes) -> bytes:
    initial_value: int = int(binascii.hexlify(base64.b64decode(iv)), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=initial_value)
    aes = AES.new(base64.b64decode(key), AES.MODE_CTR, counter=ctr)
    return aes.decrypt(ciphertext)


def decrypted_datakey(dks_url: str, certificate: str, key: str, dks_certificate: str, encrypting_key_id: str,
                      encrypted_key: str) -> str:
    response = requests.post(f"{dks_url}/datakey/actions/decrypt",
                             params={'keyId': encrypting_key_id},
                             data=encrypted_key,
                             cert=(certificate, key), verify=dks_certificate).json()
    return response['plaintextDataKey']


def object_contents(s3_object: dict):
    stream = s3_object['Body']
    try:
        return stream.read()
    finally:
        stream.close()


def client(use_localstack: bool):
    return boto3.client(service_name="s3",
                        endpoint_url="http://aws:4566",
                        use_ssl=False,
                        aws_access_key_id="ACCESS_KEY",
                        aws_secret_access_key="SECRET_KEY") if use_localstack \
        else boto3.client(service_name="s3")


def command_line_args():
    parser = argparse.ArgumentParser(description='Read, decrypts a record from the corporate memory store.')
    parser.add_argument('-l', '--localstack', default=False, action="store_true", help='Target localstack instance.')
    parser.add_argument('dks_url', help='URL of the data key service.')
    parser.add_argument('key', help='This server\'s key.')
    parser.add_argument('certificate', help='This server\'s certificate.')
    parser.add_argument('dks_certificate', help='The DKS CA certificate for mutual authentication.')
    parser.add_argument('bucket', help='The bucket with the input file.')
    parser.add_argument('path', help='The path to/key of the input file.')
    return parser.parse_args()


if __name__ == '__main__':
    main()
