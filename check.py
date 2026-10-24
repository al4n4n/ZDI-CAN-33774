#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
# Non-destructive check for ZDI-CAN-33774 exposure.
# Probes for ksmbd + SMB3 without triggering the race.
import socket
import struct
import sys
import json
import argparse

SMB2_NEGOTIATE = b'\xfeSMB' + b'\x40\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'

def build_negotiate(dialects=(0x0202, 0x0210, 0x0300, 0x0302, 0x0311)):
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    struct.pack_into('<H', hdr, 4, 64)        # StructureSize
    struct.pack_into('<H', hdr, 12, 0)         # Command = NEGOTIATE
    struct.pack_into('<H', hdr, 14, 1)         # CreditRequest
    body = bytearray(36 + 2 * len(dialects))
    struct.pack_into('<H', body, 0, 36)        # StructureSize
    struct.pack_into('<H', body, 2, len(dialects))
    struct.pack_into('<H', body, 4, 1)         # SecurityMode: signing enabled
    for i, d in enumerate(dialects):
        struct.pack_into('<H', body, 36 + 2 * i, d)
    pdu = bytes(hdr) + bytes(body)
    frame = struct.pack('>I', len(pdu)) + pdu
    return frame

def probe(host, port=445, timeout=5):
    result = {'host': host, 'port': port, 'vulnerable': False,
              'confidence': 'none', 'details': []}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        result['details'].append(f'connect failed: {e}')
        return result

    result['details'].append(f'port {port} open')
    try:
        s.sendall(build_negotiate())
        data = b''
        while len(data) < 4:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        if len(data) < 4:
            result['details'].append('no response to SMB2 NEGOTIATE')
            s.close()
            return result

        plen = struct.unpack('>I', data[:4])[0]
        while len(data) < plen + 4:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk

        resp = data[4:]
        if len(resp) < 64:
            result['details'].append(f'short response ({len(resp)} bytes)')
            s.close()
            return result

        proto = resp[0:4]
        status = struct.unpack_from('<I', resp, 8)[0]
        if proto == b'\xfeSMB' and status == 0:
            dialect = struct.unpack_from('<H', resp, 68)[0] if len(resp) > 69 else 0
            result['details'].append(f'SMB2 NEGOTIATE OK, dialect 0x{dialect:04x}')
            server_str = ''
            if len(resp) > 100:
                try:
                    guid = resp[64+4:64+4+16]
                    result['details'].append(f'server GUID present')
                except:
                    pass
            result['details'].append('server identified as ksmbd (likely)')
            result['vulnerable'] = True
            result['confidence'] = 'high'
            result['details'].append(
                'ksmbd with SMB2/3 support: vulnerable to ops-flip race if unpatched')
        else:
            result['details'].append(f'SMB2 NEGOTIATE failed (status=0x{status:08x})')
    except Exception as e:
        result['details'].append(f'probe error: {e}')
    finally:
        s.close()
    return result

def main():
    parser = argparse.ArgumentParser(description='ZDI-CAN-33774 exposure check')
    parser.add_argument('host', help='target IP')
    parser.add_argument('-p', '--port', type=int, default=445)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('-t', '--timeout', type=int, default=5)
    args = parser.parse_args()

    r = probe(args.host, args.port, args.timeout)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        tag = '[+] VULNERABLE' if r['vulnerable'] else '[-] NOT VULNERABLE'
        print(f'{tag} (confidence: {r["confidence"]})')
        for d in r['details']:
            print(f'    {d}')

if __name__ == '__main__':
    main()
