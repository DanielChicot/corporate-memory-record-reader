#!/bin/env python
import argparse
import base64
import binascii
import json
import re

import happybase as happybase
import requests as requests

from Crypto.Cipher import AES
from Crypto.Util import Counter


def main():
    args = command_line_args()
    record = hbase_record(args)
    message = record['message']
    encryption = message['encryption']
    decrypted_key = decrypted_datakey(args, encryption)
    decrypted_db_object = decrypt(decrypted_key, encryption['initialisationVector'], message['dbObject'])
    print(decrypted_db_object)


def decrypted_datakey(args, encryption):
    encrypting_key_id = encryption['keyEncryptionKeyId']
    encrypted_key = encryption['encryptedEncryptionKey']
    response = requests.post(f"{args.dks_url}/datakey/actions/decrypt", params={'keyId': encrypting_key_id},
                             data=encrypted_key,
                             cert=(args.certificate, args.key), verify=args.dks_certificate).json()
    return response['plaintextDataKey']


def hbase_record(args):
    checksum = binascii.crc32(args.id.encode("ASCII"), 0).to_bytes(4, 'little')
    # printable_checksum = checksum.hex().upper()
    # escaped = re.sub("(..)", r"\\x\1", printable_checksum)
    # printable_id = f"{escaped}{args.id}"
    hbase_id = checksum + args.id.encode("ASCII")
    connection = happybase.Connection("hbase")
    connection.open()
    table = connection.table(args.table)
    row = table.row(hbase_id)
    record = json.loads(row[b'cf:record'].decode())
    return record


def decrypt(key, iv, ciphertext):
    iv_int = int(binascii.hexlify(base64.b64decode(iv)), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(base64.b64decode(key), AES.MODE_CTR, counter=ctr)
    return aes.decrypt(base64.b64decode(ciphertext)).decode()


def command_line_args():
    parser = argparse.ArgumentParser(description='Read and decrypta record from the corporate memory store.')
    parser.add_argument('dks_url', help='URL of the data key service.')
    parser.add_argument('key', help='This server\'s private key.')
    parser.add_argument('certificate', help='This server\'s certificate.')
    parser.add_argument('dks_certificate', help='The DKS CA certificate for mutual authentication.')
    parser.add_argument('table', help='The table to fetch the record from.')
    parser.add_argument('id', help='The id of the record to fetch.')
    return parser.parse_args()


if __name__ == '__main__':
    main()
