"""Finite local WSS BookTicker replay. Requires websockets; never changes networking."""
import argparse
import asyncio
import csv
import ssl
import time


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8443)
    p.add_argument('--cert', required=True)
    p.add_argument('--key', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--rate', type=int, default=100)
    p.add_argument('--count', type=int, default=10000)
    p.add_argument('--burst', type=int, default=1)
    p.add_argument('--wait-seconds', type=int, default=60)
    args = p.parse_args()
    if not (1 <= args.rate <= 100000 and 1 <= args.count <= 1000000
            and 1 <= args.burst <= 10000 and 0 <= args.port <= 65535
            and 1 <= args.wait_seconds <= 3600):
        p.error('rate/count/burst/port/wait outside supported bounds')
    if args.count / args.rate > 3600:
        p.error('replay duration must be <=3600 seconds')
    return args


async def run(args):
    from websockets.asyncio.server import serve
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    # Prepare payloads and storage outside the send interval.
    payloads = [f'{{"u":{i},"s":"BTCUSDT","b":"{10000+i%100}.01",'
                '"B":"1.1234","a":"10101.02","A":"2.5"}'
                for i in range(1, args.count + 1)]
    rows = []
    finished = asyncio.Event()
    started = False
    failure = None

    async def handler(connection):
        nonlocal started, failure
        if started:
            await connection.close()
            return
        started = True
        origin = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        try:
            for i, payload in enumerate(payloads):
                scheduled = origin + (i // args.burst) * args.burst * 10**9 // args.rate
                delay = (scheduled - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
                await asyncio.sleep(max(0, delay))
                sent = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                await asyncio.wait_for(connection.send(payload), timeout=5)
                rows.append((i + 1, sent, scheduled))
            await asyncio.sleep(2)  # Drain in-flight messages before closing.
        except Exception as error:
            failure = error
        finally:
            finished.set()

    # Exclusive output avoids overwriting a previous run. CSV writes happen after replay.
    with open(args.output, 'x', newline='') as output:
        try:
            async with serve(handler, args.bind, args.port, ssl=context, compression=None,
                             max_size=65536, ping_interval=None) as server:
                port = server.sockets[0].getsockname()[1]
                print(f'Listening on {args.bind}:{port}; count={args.count} rate={args.rate}',
                      flush=True)
                await asyncio.wait_for(finished.wait(), args.wait_seconds + args.count / args.rate + 10)
        finally:
            writer = csv.writer(output)
            writer.writerow(('update_id', 'send_ns', 'scheduled_ns'))
            writer.writerows(rows)
            print(f'sent={len(rows)} (send API completed); output={args.output}')
    if failure:
        raise failure


if __name__ == '__main__':
    asyncio.run(run(arguments()))
