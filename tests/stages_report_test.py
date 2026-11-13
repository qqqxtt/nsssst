"""Private CSV fixtures and startup validation; no network or EAL startup."""
import csv
import os
import pathlib
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix='nsst-stages-') as folder:
    root = pathlib.Path(folder)
    result = subprocess.run([sys.argv[1], str(root/'sample')], capture_output=True, text=True, check=True, timeout=5)
    for stage in ('packet_to_tcp', 'tls', 'json'):
        with (root/f'sample.{stage}.csv').open() as stream:
            reader = csv.DictReader(stream)
            assert reader.fieldnames == ['elapsed_ns', 'bytes', 'connection_id', 'gap_ns']
            rows = list(reader)
        assert [int(r['elapsed_ns']) for r in rows] == [30, 40]
        assert f'stage={stage} seen=4 warmup=1 overflow=1 invalid=1' in result.stdout
        assert f'{stage}: n=2' in result.stdout
        assert f'{stage}.hot: n=2' in result.stdout and f'{stage}.cold: n=0' in result.stdout
    assert len(list(root.iterdir())) == 3
    subprocess.run([sys.argv[1], str(root/'unused'), str(root/'tcp')], check=True, capture_output=True, timeout=5)
    assert (root/'tcp.packet_to_tcp.csv').exists()
    assert not (root/'tcp.tls.csv').exists() and not (root/'tcp.json.csv').exists()
    env = dict(os.environ, BENCH_STAGES='1')
    env.pop('BINANCE_SYMBOL', None)
    failure = subprocess.run([sys.argv[2]], env=env, capture_output=True, text=True, timeout=5)
    assert failure.returncode != 0 and 'BENCH_STAGES requires' in failure.stderr, failure.stderr
    env.update(BENCH_TCP_ONLY='1', BINANCE_SYMBOL='BTCUSDT')
    failure = subprocess.run([sys.argv[2]], env=env, capture_output=True, text=True, timeout=5)
    assert failure.returncode != 0 and 'BENCH_TCP_ONLY cannot' in failure.stderr
print('PASS: three CSV schemas, independent warmup/overflow, and startup guard')
