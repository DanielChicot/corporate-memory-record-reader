#!/usr/bin/python3

import argparse
import base64
import binascii
import json

import happybase as happybase
import requests as requests
from Crypto.Cipher import AES
from Crypto.Util import Counter


def main():
    args = command_line_args()
    record = hbase_record(args.table, args.id)
    message = record['message']
    encryption_metadata = message['encryption']
    decrypted_key = decrypted_datakey(args.dks_url, args.certificate, args.key, args.dks_certificate,
                                      encryption_metadata)
    decrypted_db_object = decrypted(decrypted_key, encryption_metadata['initialisationVector'], message['dbObject'])
    print(decrypted_db_object)


def hbase_record(table: str, uc_id: str) -> dict:
    checksum = binascii.crc32(uc_id.encode("ASCII"), 0).to_bytes(4, 'big')
    hbase_id: bytes = checksum + uc_id.encode("ASCII")
    connection = happybase.Connection()
    connection.open()
    table = connection.table(table)
    row = table.row(hbase_id)
    record = json.loads(row[b'cf:record'].decode())
    connection.close()
    return record


def decrypted_datakey(dks_url: str, certificate: str, key: str, dks_certificate: str, encryption) -> str:
    encrypting_key_id = encryption['keyEncryptionKeyId']
    encrypted_key = encryption['encryptedEncryptionKey']
    response = requests.post(f"{dks_url}/datakey/actions/decrypt",
                             params={'keyId': encrypting_key_id},
                             data=encrypted_key,
                             cert=(certificate, key), verify=dks_certificate).json()
    return response['plaintextDataKey']


def decrypted(key: str, iv: str, ciphertext: str) -> str:
    initial_value: int = int(binascii.hexlify(base64.b64decode(iv)), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=initial_value)
    aes = AES.new(base64.b64decode(key), AES.MODE_CTR, counter=ctr)
    return aes.decrypt(base64.b64decode(ciphertext)).decode()


def command_line_args():
    parser = argparse.ArgumentParser(description='Read, decrypts a record from the corporate memory store.')
    parser.add_argument('dks_url', help='URL of the data key service.')
    parser.add_argument('key', help='This server\'s private key.')
    parser.add_argument('certificate', help='This server\'s certificate.')
    parser.add_argument('dks_certificate', help='The DKS CA certificate for mutual authentication.')
    parser.add_argument('table', help='The table to fetch the record from.')
    parser.add_argument('id', help='The id of the record to fetch.')
    return parser.parse_args()


if __name__ == '__main__':
    main()
