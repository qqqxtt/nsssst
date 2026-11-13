"""TCP byte relay for the live-market demo.

The listening socket is created in the current (private demo) network namespace; the process
then joins --netns (the host namespace) before connecting upstream. TLS is never terminated:
nsst and the exchange negotiate TLS end to end and nsst verifies the real certificate, so the
relay only ever sees ciphertext. No iptables, NAT or IP forwarding is involved.
"""
import argparse
import ctypes
import os
import signal
import socket
import sys
import threading

CLONE_NEWNET = 0x40000000


def join_netns(path):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(path, os.O_RDONLY)
    try:
        if libc.setns(fd, CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), f'setns({path})')
    finally:
        os.close(fd)


def pump(source, destination, counts, key):
    try:
        while data := source.recv(65536):
            destination.sendall(data)
            counts[key] += len(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)  # propagate EOF; the other direction continues
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--listen', required=True, help='address in the demo namespace')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--upstream', required=True, help='exchange IPv4, resolved by the caller')
    parser.add_argument('--netns', required=True, help='network namespace with internet access')
    parser.add_argument('--accept-timeout', type=float, default=20)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen, args.port))
    listener.listen(1)
    join_netns(args.netns)  # Before any thread starts: threads inherit the namespace.
    print(f'Relay ready: {args.listen}:{args.port} -> {args.upstream}:{args.port}', flush=True)

    listener.settimeout(args.accept_timeout)
    client, peer = listener.accept()
    listener.close()
    upstream = socket.create_connection((args.upstream, args.port), timeout=10)
    upstream.settimeout(None)
    client.settimeout(None)
    for s in (client, upstream):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f'Relaying {peer[0]}:{peer[1]} <-> {args.upstream}:{args.port} (ciphertext only)',
          flush=True)

    counts = {'to_exchange': 0, 'from_exchange': 0}
    threads = [threading.Thread(target=pump, args=(client, upstream, counts, 'to_exchange'),
                                daemon=True),
               threading.Thread(target=pump, args=(upstream, client, counts, 'from_exchange'),
                                daemon=True)]
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    finally:
        print(f'Relay closed: {counts["to_exchange"]} bytes to the exchange, '
              f'{counts["from_exchange"]} bytes from it', flush=True)


if __name__ == '__main__':
    main()
