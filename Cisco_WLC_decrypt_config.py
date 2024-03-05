#!/usr/bin/env python3

import argparse
from Crypto.Cipher import AES  # pip install pycryptodome
from binascii import hexlify, unhexlify

def decrypt(iv, encrypted, hex=False):
    if iv == "0":
        return bytearray.fromhex(encrypted).decode('utf-8')

    enc_key = unhexlify("834156f9940f09c0a8d00f019f850005")
    decipher = AES.new(enc_key, AES.MODE_CBC, unhexlify(iv))
    decoded = decipher.decrypt(unhexlify(encrypted))
    if hex:
        return hexlify(decoded).decode('utf-8')
    else:
        return decoded.rstrip(b'\x0c').rstrip(b'\x0a').split(b'\0')[0].decode('utf-8')

def parse_filename(filename):

    # Collect WLAN names
    wlan_names = []
    with (open(filename) as wlc_config_file):
        for wlc_config_line in wlc_config_file:
            if "config wlan create" in wlc_config_line:
                line = wlc_config_line.split()
                if wlc_config_line.rstrip()[-1:] == '"':
                    delimiter = '"'
                else:
                    delimiter = ' '
                wlan_item = {
                    "id": line[3],
                    "name": wlc_config_line.split(delimiter)[-2]
                }
                wlan_names.append(wlan_item)

    # Process encrypted items
    with (open(filename) as wlc_config_file):
        for wlc_config_line in wlc_config_file:
            line = wlc_config_line.split()

            if "config tacacs auth add encrypt 1" in wlc_config_line:
                host = line[6]
                secret = decrypt(line[10], line[13][:int(line[12])*2])
                print(f"Tacacs+ host: {host}, secret: {secret}")

            if "config ap mgmtuser add encrypt" in wlc_config_line:
                username = line[6]
                secret = decrypt(line[9], line[12][:int(line[11])*2])
                print(f"ap mgmtuser: {username}, password: {secret}")

            if "config netuser add encrypt" in wlc_config_line:
                username = line[5]
                secret = decrypt(line[8], line[11][:int(line[10])*2])
                print(f"netuser: {username}, password: {secret}")

            if "config radius auth add encrypt 1" in wlc_config_line:
                host = line[6]
                secret = decrypt(line[10], line[13][:int(line[12])*2])
                print(f"Radius host: {host}, secret: {secret}")

            if "config mgmtuser add encrypt" in wlc_config_line:
                username = line[4]
                secret = decrypt(line[6], line[9][:int(line[8])*2])
                print(f"mgmtuser: {username}, password: {secret}")

            if "transfer upload encrypt password 1" in wlc_config_line:
                secret = decrypt(line[5], line[8][:int(line[7])*2])
                print(f"Upload password: {secret}")

            if "transfer download encrypt password 1" in wlc_config_line:
                secret = decrypt(line[5], line[8][:int(line[7])*2])
                print(f"Download password: {secret}")

            if "config wlan security wpa akm psk set-key hex encrypt" in wlc_config_line:
                enc_mode = line[9]
                enc_secret = line[13][:int(line[12])*2]
                wlan_name = next(item for item in wlan_names if item["id"] == line[14])["name"]
                if enc_mode == "1":
                    psk = decrypt(line[10], enc_secret, True)[:64]
                elif enc_mode == "0":
                    psk = enc_secret[:64]
                else:
                    psk = "* Unsupported encrypt mode! *"
                print(f"SSID: {wlan_name}, WLAN ID: {line[14]}, PSK hex: {psk}")


def main():
    parser = argparse.ArgumentParser(
        prog='Cisco_WLC_decrypt_config',
        description='Decrypt Cisco WLC configuration')
    parser.add_argument('filename')
    args = parser.parse_args()
    parse_filename(args.filename)

if __name__ == '__main__':
    main()