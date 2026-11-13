"""Test the receive-only DPDK TCP server from the peer network namespace."""

import argparse
import socket
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.0.2.2")
    parser.add_argument("--port", type=int, default=19000)
    parser.add_argument("--message", default="hello TCP")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval-ms", type=float, default=0)
    parser.add_argument("--bytes", type=int, default=None, dest="payload_bytes")
    args = parser.parse_args()
    if not 1 <= args.count <= 1000000 or not 0 <= args.interval_ms <= 60000:
        parser.error("invalid count or interval")
    if args.payload_bytes is not None and not 1 <= args.payload_bytes <= 65536:
        parser.error("bytes must be 1..65536")
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error("port must be 1..65535 and timeout must be positive")

    payload = args.message.encode("utf-8") if args.payload_bytes is None else b"x" * args.payload_bytes
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
            print(f"连接成功：{sock.getsockname()} -> {sock.getpeername()}", flush=True)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for i in range(args.count):
                sock.sendall(payload)
                if args.interval_ms and i + 1 < args.count:
                    time.sleep(args.interval_ms / 1000)
            print(f"已发送 {args.count} 次，共 {len(payload) * args.count} 字节", flush=True)
            sock.shutdown(socket.SHUT_WR)
            # The current server receives data and closes after our FIN; it sends no echo.
            if sock.recv(1) != b"":
                print("FAIL：收到非预期应用数据，当前 Demo 应直接返回 EOF", file=sys.stderr)
                return 1
            print("PASS：连接建立、发送及 FIN/EOF 关闭流程完成")
            return 0
    except OSError as exc:
        print(f"FAIL：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
