#!/usr/bin/env bash
# Private veth lab for the DPDK ARP / ICMP / UDP demo.
set -euo pipefail

STACK_NS=stack
PEER_NS=peer
STACK_IF=dpdk0
PEER_IF=peer0
STACK_MAC=02:00:00:00:00:02
PEER_MAC=02:00:00:00:00:01
PEER_IP=192.0.2.1/24
# EXIT traps run after function-local variables may have left scope.
declare -a CREATED_NAMESPACES=()

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'HELP'
Usage: sudo ./scripts/netns_lab.sh {up|status|down}

  up      Create the two namespaces and veth pair, or reuse matching existing ones.
          Configure peer0 as 192.0.2.1/24; disable its TX checksum offload.
          dpdk0 has no Linux IPv4: set LOCAL_IP=192.0.2.2 in the DPDK program.
  status  Show interfaces, IPv4 addresses, processes and peer0 checksum offload.
  down    Remove matching lab namespaces, only if neither contains any processes.

Requires: iproute2 and util-linux (flock); ethtool is also required for up.
This script does not install packages or start/stop the DPDK program.
HELP
}

ns_exists() {
    local listing name rest
    listing=$(ip netns list) || fail 'Cannot list network namespaces'
    while read -r name rest; do
        if [[ "$name" == "$1" ]]; then return 0; fi
    done <<< "$listing"
    return 1
}

check_interface() {
    local namespace=$1 interface=$2 mac=$3 info links
    links=$(ip -n "$namespace" -o link show) || fail "Cannot inspect $namespace"
    local -a interfaces
    mapfile -t interfaces <<< "$links"
    ((${#interfaces[@]} == 2)) || fail "$namespace must contain only lo and $interface"
    info=$(ip -n "$namespace" -d -o link show dev "$interface") || fail "Missing $namespace/$interface"
    [[ "$info" == *"link/ether $mac "* && "$info" == *" veth "* && "$info" == *" mtu 1500 "* ]] ||
        fail "Unexpected MAC, interface type or MTU on $namespace/$interface; nothing will be replaced"
}

check_environment() {
    check_interface "$STACK_NS" "$STACK_IF" "$STACK_MAC"
    check_interface "$PEER_NS" "$PEER_IF" "$PEER_MAC"
    local stack_ip peer_ip stack_link peer_link stack_index peer_index
    stack_ip=$(ip -n "$STACK_NS" -o -4 addr show) || fail 'Cannot inspect stack IPv4 addresses'
    [[ -z "$stack_ip" || "$stack_ip" == *' lo '* ]] || fail 'Unexpected Linux IPv4 on stack side'
    stack_ip=$(ip -n "$STACK_NS" -o -4 addr show dev "$STACK_IF") || fail 'Cannot inspect dpdk0 IPv4'
    [[ -z "$stack_ip" ]] || fail 'dpdk0 must not have a Linux IPv4 address'
    peer_ip=$(ip -n "$PEER_NS" -o -4 addr show dev "$PEER_IF") || fail 'Cannot inspect peer0 IPv4'
    [[ "$peer_ip" == *"inet $PEER_IP "* && "$peer_ip" != *$'\n'* ]] ||
        fail "Expected only $PEER_IP on $PEER_IF"
    stack_link=$(ip -n "$STACK_NS" -o link show dev "$STACK_IF") || fail 'Cannot inspect veth pair'
    peer_link=$(ip -n "$PEER_NS" -o link show dev "$PEER_IF") || fail 'Cannot inspect veth pair'
    [[ "$stack_link" =~ ^([0-9]+): ]] || fail 'Cannot read stack interface index'
    stack_index=${BASH_REMATCH[1]}
    [[ "$peer_link" =~ ^([0-9]+): ]] || fail 'Cannot read peer interface index'
    peer_index=${BASH_REMATCH[1]}
    [[ "$stack_link" == *"@if${peer_index}:"* && "$peer_link" == *"@if${stack_index}:"* ]] ||
        fail 'The two interfaces are not the expected veth pair'
}

check_idle() {
    local namespace=$1 pids
    pids=$(ip netns pids "$namespace") || fail "Cannot inspect processes in $namespace"
    [[ -z "$pids" ]] || fail "$namespace has processes ($pids). Stop the DPDK program, captures and test shells first"
}

# Roll back only namespaces created by this invocation, never pre-existing ones.
rollback_setup() {
    local code=$1 namespace
    trap - EXIT
    if ((code != 0)); then
        for namespace in "${CREATED_NAMESPACES[@]}"; do
            local pids
            if pids=$(ip netns pids "$namespace") && [[ -z "$pids" ]]; then
                ip netns del "$namespace" || printf 'Cleanup failed: %s\n' "$namespace" >&2
            else
                printf 'Left %s intact: cannot confirm it is idle\n' "$namespace" >&2
            fi
        done
    fi
    exit "$code"
}

up() {
    command -v ethtool >/dev/null || fail 'Install ethtool first: sudo apt install ethtool'
    local stack_exists=0 peer_exists=0
    if ns_exists "$STACK_NS"; then stack_exists=1; fi
    if ns_exists "$PEER_NS"; then peer_exists=1; fi
    ((stack_exists == peer_exists)) || fail 'Only one lab namespace exists; inspect with status before repairing it'
    CREATED_NAMESPACES=()
    trap 'rollback_setup $?' EXIT
    if ((stack_exists == 0)); then
        ip netns add "$STACK_NS"
        CREATED_NAMESPACES+=("$STACK_NS")
        ip netns add "$PEER_NS"
        CREATED_NAMESPACES+=("$PEER_NS")
        # Create inside the private namespace, avoiding interface names in the host.
        ip -n "$STACK_NS" link add "$STACK_IF" type veth peer name "$PEER_IF"
        ip -n "$STACK_NS" link set "$PEER_IF" netns "$PEER_NS"
        ip -n "$STACK_NS" link set "$STACK_IF" address "$STACK_MAC" mtu 1500
        ip -n "$PEER_NS" link set "$PEER_IF" address "$PEER_MAC" mtu 1500
        ip -n "$PEER_NS" addr add "$PEER_IP" dev "$PEER_IF"
    fi
    check_environment
    ip -n "$STACK_NS" link set lo up
    ip -n "$PEER_NS" link set lo up
    ip -n "$STACK_NS" link set "$STACK_IF" up
    ip -n "$PEER_NS" link set "$PEER_IF" up
    ip netns exec "$PEER_NS" ethtool -K "$PEER_IF" tx off
    trap - EXIT
    CREATED_NAMESPACES=()
    printf 'Ready: %s/%s <-> %s/%s (%s)\n' "$STACK_NS" "$STACK_IF" "$PEER_NS" "$PEER_IF" "$PEER_IP"
    printf 'DPDK: LOCAL_IP=192.0.2.2, --vdev="net_af_packet0,iface=%s,qdisc_bypass=1"\n' "$STACK_IF"
}

status() {
    local namespace pids line
    for namespace in "$STACK_NS" "$PEER_NS"; do
        if ns_exists "$namespace"; then
            printf '\n[%s]\n' "$namespace"
            ip -n "$namespace" -br link show
            ip -n "$namespace" -br -4 addr show
            pids=$(ip netns pids "$namespace")
            printf 'Processes: %s\n' "${pids:-none}"
        else
            printf '%s: not created\n' "$namespace"
        fi
    done
    if ns_exists "$PEER_NS" && command -v ethtool >/dev/null; then
        while IFS= read -r line; do
            if [[ "$line" == tx-checksumming:* ]]; then printf '%s\n' "$line"; fi
        done < <(ip netns exec "$PEER_NS" ethtool -k "$PEER_IF")
    fi
}

down() {
    local stack_exists=0 peer_exists=0
    if ns_exists "$STACK_NS"; then stack_exists=1; fi
    if ns_exists "$PEER_NS"; then peer_exists=1; fi
    if ((stack_exists == 0 && peer_exists == 0)); then
        printf 'Lab is already down\n'
        return
    fi
    ((stack_exists == 1 && peer_exists == 1)) || fail 'Incomplete lab; refusing to remove an unverified namespace'
    check_environment
    check_idle "$STACK_NS"
    check_idle "$PEER_NS"
    ip netns del "$STACK_NS"
    ip netns del "$PEER_NS"
    printf 'Removed lab namespaces and veth pair\n'
}

main() {
    if (($# != 1)); then usage; return 1; fi
    case "$1" in
        -h|--help) usage; return ;;
        up|status|down) ;;
        *) usage; return 1 ;;
    esac
    ((EUID == 0)) || fail "Run with sudo: sudo $0 $1"
    command -v ip >/dev/null || fail 'Install iproute2 first: sudo apt install iproute2'
    if [[ "$1" != status ]]; then
        command -v flock >/dev/null || fail 'Install util-linux first: sudo apt install util-linux'
        exec {lab_lock_fd}>/run/dpdk-netns-lab.lock
        flock -n "$lab_lock_fd" || fail 'Another lab setup/cleanup is running'
    fi
    "$1"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
