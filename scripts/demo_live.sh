#!/usr/bin/env bash
# Live Binance BookTicker through the user-space stack, with stage timing.
#
#   nsst (DPDK af_packet on recv0) --veth--> send0 192.0.2.1:443  [private network namespace]
#                                               relay.py: ciphertext only
#                                            exchange:443          [host network namespace]
#
# TLS 1.3 runs end to end between nsst and the exchange, and nsst verifies the exchange's real
# certificate. Everything runs in fresh network and mount namespaces created by `unshare`: the
# veth pair and the /etc/hosts override disappear when the script exits. No iptables, NAT,
# IP forwarding or host interface changes.
#
# Requires: sudo, iproute2, ethtool, util-linux (unshare), python3, DPDK with net_af_packet,
# and outbound access to the exchange on port 443 from this machine.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD

: "${BINANCE_HOST:=stream.binance.com}" # data-stream.binance.vision also serves market data
: "${BINANCE_PORT:=443}"
: "${SYMBOL:=BTCUSDT}"
: "${DEMO_SECONDS:=30}"
: "${CPU:=2}"       # receive core; on WSL2 avoid CPU 0 (it takes the Hyper-V interrupts)
: "${RELAY_CPU:=6}" # relay core
: "${BUILD:=$root/build/release}"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

if [[ ${1:-} != --inside ]]; then
    step "Build (Release) -> $BUILD"
    if [[ ! -x $BUILD/nsst ]]; then
        cmake -S . -B "$BUILD" -DBUILD_TESTING=OFF >/dev/null
        cmake --build "$BUILD" --parallel
    fi
    # Resolve now: inside the demo namespace the host name is pinned to the relay address.
    upstream=$(getent ahostsv4 "$BINANCE_HOST" | awk 'NR == 1 { print $1 }')
    [[ -n $upstream ]] || fail "cannot resolve $BINANCE_HOST"
    timeout 5 bash -c "exec 3<>/dev/tcp/$upstream/$BINANCE_PORT" 2>/dev/null ||
        fail "$BINANCE_HOST ($upstream) port $BINANCE_PORT is unreachable from this machine;
       try BINANCE_HOST=data-stream.binance.vision or a machine with access to Binance"
    printf '%s resolves to %s; port %s reachable\n' "$BINANCE_HOST" "$upstream" "$BINANCE_PORT"
    work=$(mktemp -d "${TMPDIR:-/tmp}/nsst-live.XXXXXX")
    step "Private network + mount namespace (needs sudo)"
    sudo env BINANCE_HOST="$BINANCE_HOST" BINANCE_PORT="$BINANCE_PORT" SYMBOL="$SYMBOL" \
        DEMO_SECONDS="$DEMO_SECONDS" CPU="$CPU" RELAY_CPU="$RELAY_CPU" BUILD="$BUILD" \
        UPSTREAM="$upstream" HOST_NETNS="/proc/$$/ns/net" WORK="$work" \
        ${CA_FILE:+CA_FILE="$CA_FILE"} \
        unshare --net --mount -- bash "$root/scripts/demo_live.sh" --inside
    printf '\nLogs and CSV files: %s\n' "$work"
    exit 0
fi

# ---- Inside the private namespaces (root). ----
: "${UPSTREAM:?}" "${HOST_NETNS:?}" "${WORK:?}"
relay_pid=
trap '[[ -n $relay_pid ]] && kill "$relay_pid" 2>/dev/null; wait 2>/dev/null || true' EXIT

mount --make-rprivate /
printf '127.0.0.1 localhost\n192.0.2.1 %s\n' "$BINANCE_HOST" >"$WORK/hosts"
mount --bind "$WORK/hosts" /etc/hosts # visible to this mount namespace only
ip link set lo up
ip link add send0 type veth peer name recv0
ip addr add 192.0.2.1/24 dev send0
ip link set send0 up
ip link set recv0 up
ethtool -K send0 tx off >/dev/null # kernel would otherwise leave TCP checksums unfilled

taskset -c "$RELAY_CPU" python3 "$root/scripts/relay.py" --listen 192.0.2.1 \
    --port "$BINANCE_PORT" --upstream "$UPSTREAM" --netns "$HOST_NETNS" >"$WORK/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 50); do
    grep -q 'Relay ready' "$WORK/relay.log" 2>/dev/null && break
    kill -0 "$relay_pid" 2>/dev/null || { cat "$WORK/relay.log"; exit 1; }
    sleep 0.1
done
grep -q 'Relay ready' "$WORK/relay.log" || { cat "$WORK/relay.log"; exit 1; }

step "Subscribing to $SYMBOL bookTicker via $BINANCE_HOST for ${DEMO_SECONDS}s"
env LOCAL_IP=192.0.2.2 BINANCE_SYMBOL="$SYMBOL" BINANCE_HOST="$BINANCE_HOST" \
    BINANCE_PORT="$BINANCE_PORT" BENCH_SECONDS="$DEMO_SECONDS" \
    BENCH_OUTPUT_PREFIX="$WORK/stages" ${CA_FILE:+CA_FILE="$CA_FILE"} \
    "$BUILD/nsst" -l "$CPU" -m 128 --no-pci --no-huge --no-shconf --no-telemetry \
    --file-prefix=nsst-live --vdev="net_af_packet0,iface=recv0,qdisc_bypass=1" \
    >"$WORK/nsst.log" 2>&1 || { cat "$WORK/nsst.log"; exit 1; }

kill "$relay_pid" 2>/dev/null || true
wait "$relay_pid" 2>/dev/null || true
relay_pid=
grep -E '^Relay' "$WORK/relay.log"
if grep -qE 'Binance (disconnected|invalid)' "$WORK/nsst.log"; then
    grep -E 'Binance (disconnected|invalid)' "$WORK/nsst.log" >&2
fi
quotes=$(($(wc -l <"$WORK/stages.quotes.csv" 2>/dev/null || echo 1) - 1))
((quotes > 0)) || { cat "$WORK/nsst.log"; fail "no quotes received"; }
step "Stage timing over $quotes quotes (ns)"
grep -E '^(runtime|stage=)|^[a-z_.]+: n=' "$WORK/nsst.log"
