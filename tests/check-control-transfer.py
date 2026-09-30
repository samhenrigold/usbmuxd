#!/usr/bin/env python3
"""Real daemon/TCP fake guest: delayed EP0 packets, real short packet and ZLP."""
import argparse
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

HEADER = struct.Struct('<BBBh')


def read(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise EOFError
        data += part
    return data


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(binary, serial_zlp):
    usb, mux = port(), port()
    config = bytes([9, 2, 149, 0, 1, 1, 0, 0x80, 50,
                    9, 4, 0, 0, 2, 255, 254, 2, 0,
                    7, 5, 0x81, 2, 0, 2, 0, 7, 5, 2, 2, 0, 2, 0]) + bytes([117, 0xff]) + bytes(115)
    descriptor = bytes([18, 1, 0, 2, 0, 0, 0, 64, 0xac, 5, 0x9a, 0x12, 0, 1, 0, 0, 1, 1])
    serial = bytes([64, 3]) + ('A' * 31).encode('utf-16-le') if serial_zlp else bytes([18, 3]) + '12345678'.encode('utf-16-le')
    state = {'delayed_bytes': 0, 'naks': 0, 'serial_done': False, 'zero': False}
    errors = []
    def guest():
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    s = socket.create_connection(('127.0.0.1', usb), timeout=.5)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.02)
            with s:
                s.settimeout(5)
                payload, offset, delayed, serial_read = b'', 0, False, False
                while not state['serial_done']:
                    addr, ep, flags, n = HEADER.unpack(read(s, HEADER.size))
                    out = read(s, n) if n > 0 and not ep & 128 else b''
                    data, result = b'', n
                    if flags & 8:
                        data = struct.pack('<IHHI', 0x42535554, 1, 0, 32767)
                        result = len(data)
                    elif flags & 1:
                        kind, request, value, index, length = struct.unpack('<BBHHH', out)
                        offset, delayed, serial_read = 0, False, False
                        if request == 6:
                            payload = descriptor if value >> 8 == 1 else config if value >> 8 == 2 else bytes([4, 3, 9, 4]) if value & 255 == 0 else serial
                            payload = payload[:length]
                            delayed = value >> 8 == 2 and length == 149
                            serial_read = value >> 8 == 3 and value & 255 != 0
                        else:
                            payload = b''
                    elif ep == 128 and n:
                        if delayed and offset == 128 and state['naks'] < 60:
                            result = -2
                            state['naks'] += 1
                        else:
                            data = payload[offset:offset+min(n, 64)]
                            offset += len(data)
                            result = len(data)
                            if delayed:
                                state['delayed_bytes'] = offset
                            if serial_read and not data:
                                state['zero'] = True
                    elif ep == 0 and n == 0 and serial_read:
                        assert offset == len(serial)
                        state['serial_done'] = True
                    s.sendall(HEADER.pack(addr, ep, flags, result) + (data if ep & 128 and result > 0 else b''))
        except Exception as error:
            errors.append(error)
    with tempfile.TemporaryDirectory() as td:
        import os
        env = os.environ | {'USBMUXD_QEMU_ADDR': f'127.0.0.1:{usb}', 'USBMUXD_QEMU_DELAY': '0'}
        with (Path(td) / 'daemon.log').open('w') as log:
            proc = subprocess.Popen([str(binary), '-f', '-v', '-S', f'127.0.0.1:{mux}', '-P', 'NONE', '-C', td], env=env, stdout=log, stderr=subprocess.STDOUT)
            thread = threading.Thread(target=guest)
            started = time.monotonic()
            thread.start()
            thread.join(timeout=8)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill();proc.wait()
        text = (Path(td) / 'daemon.log').read_text()
        assert not thread.is_alive(), text
        assert not errors, (errors, text)
        assert state['delayed_bytes'] == 149 and state['naks'] == 60, (state, text)
        assert state['serial_done'] and state['zero'] == serial_zlp, (state, text)
        assert 'Found the mux interface' in text, text
        assert time.monotonic() - started < 8, text


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--usbmuxd', type=Path, required=True)
    a = parser.parse_args()
    run(a.usbmuxd.resolve(), False)
    run(a.usbmuxd.resolve(), True)
    print('PASS: real daemon retains 149-byte control transfer across 60 NAKs; short packet and ZLP complete')
