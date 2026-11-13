#!/usr/bin/env bash
# One-command demo on a private veth pair:
#   1. the peer pings the DPDK process: ARP and ICMP are answered by the user-space stack;
#   2. a local TLS 1.3 WebSocket server replays BookTicker quotes, nsst subscribes through its
#      own TCP stack and reports per-stage and end-to-end latency.
# Requires: sudo, iproute2, ethtool, openssl, python3 (uv optional), DPDK with net_af_packet.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
build=${BUILD:-$root/build/release}
cpu=${CPU:-2}            # receive core; on WSL2 avoid CPU 0 (it takes the Hyper-V interrupts)
peer_cpu=${PEER_CPU:-6}  # replay server core
duration=${DEMO_SECONDS:-20}
rate=${DEMO_RATE:-100}   # quotes per second
work=$(mktemp -d "${TMPDIR:-/tmp}/nsst-demo.XXXXXX")
pids=()

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cleanup() {
    for pid in "${pids[@]}"; do sudo kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
wait_for() { # file pattern seconds
    for _ in $(seq $((10 * $3))); do
        grep -q "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    printf 'Timed out waiting for "%s" in %s:\n' "$2" "$1" >&2
    cat "$1" >&2
    return 1
}

step "Build (Release) -> $build"
if [[ ! -x $build/nsst ]]; then
    cmake -S . -B "$build" -DBUILD_TESTING=OFF >/dev/null
    cmake --build "$build" --parallel
fi

venv=$root/build/demo-venv
if [[ ! -x $venv/bin/python ]]; then
    step "Python environment for the replay server (websockets)"
    if command -v uv >/dev/null; then
        uv venv -q "$venv" && uv pip install -q --python "$venv/bin/python" 'websockets>=15,<18'
    else
        python3 -m venv "$venv" && "$venv/bin/pip" install -q 'websockets>=15,<18'
    fi
fi

step "Throwaway certificate for 192.0.2.1 and veth lab (namespaces: stack, peer)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=192.0.2.1 -addext 'subjectAltName=IP:192.0.2.1,DNS:192.0.2.1' \
    -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
sudo "$root/scripts/netns_lab.sh" up

# The replay finishes a few seconds before nsst stops, so every quote can be matched.
count=$((rate * (duration - 6)))
sudo ip netns exec peer taskset -c "$peer_cpu" "$venv/bin/python" scripts/book_ticker_replay.py \
    --bind 192.0.2.1 --port 8443 --cert "$work/cert.pem" --key "$work/key.pem" \
    --rate "$rate" --count "$count" --output "$work/sender.csv" >"$work/replay.log" 2>&1 &
pids+=($!)
replay=$!
wait_for "$work/replay.log" Listening 10

sudo ip netns exec stack env LOCAL_IP=192.0.2.2 \
    BINANCE_SYMBOL=BTCUSDT BINANCE_HOST=192.0.2.1 BINANCE_PORT=8443 CA_FILE="$work/cert.pem" \
    BENCH_SECONDS="$duration" BENCH_WARMUP=10 BENCH_OUTPUT_PREFIX="$work/stages" \
    "$build/nsst" -l "$cpu" -m 128 --no-pci --no-huge --no-shconf --no-telemetry \
    --vdev="net_af_packet0,iface=dpdk0,qdisc_bypass=1" >"$work/nsst.log" 2>&1 &
pids+=($!)
nsst=$!
wait_for "$work/nsst.log" "Receiving on port" 15

step "ARP + ICMP: the peer's kernel talks to the user-space stack"
sudo ip netns exec peer ip neigh flush dev peer0
sudo ip netns exec peer ping -c 3 -i 0.2 192.0.2.2
sudo ip netns exec peer ip neigh show dev peer0

step "TLS 1.3 + WebSocket BookTicker replay: $rate quotes/s for ${duration}s"
wait "$nsst" || { cat "$work/nsst.log"; exit 1; }
wait "$replay" || { cat "$work/replay.log"; exit 1; }
grep -E '^(runtime|stage=)|^[a-z_.]+: n=|^quotes' "$work/nsst.log"

step "End to end, joined by update_id (same CLOCK_MONOTONIC on both sides)"
python3 scripts/e2e_latency.py "$work/sender.csv" "$work/stages.quotes.csv"

printf '\nLogs and CSV files: %s\nRemove the lab with: sudo scripts/netns_lab.sh down\n' "$work"
