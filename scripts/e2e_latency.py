"""Join book_ticker_replay.py sender CSV with nsst <prefix>.quotes.csv by update_id.

Both sides read CLOCK_MONOTONIC on the same (WSL2) kernel, so timestamps are comparable.
  send->rx    Python send() call .. rx_burst returned the packet that completed the quote
              (websockets + kernel TLS-less TCP + veth + af_packet + PMD wait)
  rx->done    that packet entering stack.receive .. JSON parse finished (user space)
  send->done  end to end
"""
import argparse
import csv
import math


def quantiles(name, values):
    if not values:
        print(f'{name:11s} n=0')
        return
    values = sorted(values)
    q = lambda p: values[max(0, math.ceil(p * len(values)) - 1)]
    print(f'{name:11s} n={len(values)} p50={q(.5)} p90={q(.9)} p99={q(.99)} '
          f'p99.9={q(.999)} max={values[-1]} ns')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sender', help='book_ticker_replay.py --output CSV')
    parser.add_argument('quotes', help='nsst <BENCH_OUTPUT_PREFIX>.quotes.csv')
    args = parser.parse_args()
    with open(args.sender, newline='') as f:
        sent = {int(r['update_id']): int(r['send_ns']) for r in csv.DictReader(f)}
    send_rx, rx_done, send_done, missing, negative = [], [], [], 0, 0
    with open(args.quotes, newline='') as f:
        for r in csv.DictReader(f):
            update = int(r['update_id'])
            if update not in sent:
                missing += 1
                continue
            send, rx, done = sent[update], int(r['rx_ns']), int(r['done_ns'])
            if rx < send or done < rx:
                negative += 1  # e.g. quote completed in a maintenance poll, stale rx_ns
                continue
            send_rx.append(rx - send)
            rx_done.append(done - rx)
            send_done.append(done - send)
    print(f'matched={len(send_done)} unmatched={missing} discarded={negative} '
          f'sent={len(sent)}')
    quantiles('send->rx', send_rx)
    quantiles('rx->done', rx_done)
    quantiles('send->done', send_done)


if __name__ == '__main__':
    main()
