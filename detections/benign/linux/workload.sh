#!/usr/bin/env bash
# The bash -c bodies are single-quoted on purpose: "$1" there is the inner
# shell's own positional argument.
# shellcheck disable=SC2016
#
# Benign Linux workload for the live false-positive capture (capture.py).
#
# Realistic admin, developer and service activity on an Ubuntu CI runner, chosen
# to be ADJACENT to the Linux Sigma rules: it reaches the same syscalls the rules
# key on (socket families, ptrace, bpf, setns, unshare, memfd/execveat,
# perf_event_open, io_uring, add_key, pipe/splice), through the ordinary tools that
# the rules' `falsepositives:` sections name. Nothing here emulates an attack,
# nothing is destructive, and nothing leaves the runner changed: every object the
# workload creates (a temp dir, a container, a network namespace, a session key)
# is removed on exit.
#
# Rule families and the everyday activity that sits next to them:
#   T1040 raw/packet sockets  tcpdump -c on lo, ping, mtr, arping to the gateway
#   T1068 AF_ALG / xfrm       cryptsetup benchmark (AF_ALG), ip xfrm state list
#   T1068 unshare             unshare --net (a throwaway netns), ip netns add
#   T1068 add_key             keyctl add + unlink in the session keyring
#   T1068 perf_event_open     perf stat
#   T1068 pipe/splice         shell pipelines, cat into a pipe
#   T1014 bpf                 bpftool prog list, systemd-run -p IPAddressDeny=any
#   T1611 setns               docker exec (runc), nsenter -n into a container,
#                             ip netns exec
#   T1620 memfd/execveat      docker run (runc clones itself through a memfd)
#   T1622 ptrace TRACEME      gdb -batch -ex run, strace
#   T1685 io_uring            fio --ioengine=io_uring (when installed)
#   noise                     apt, pip, git, curl, make + gcc, systemctl, journalctl
#
# Every command runs under `timeout` and its failure is logged, never fatal: a
# missing tool or a flaky network call must not fail the capture. Run as root
# (capture.py runs it under sudo, with the det-eng audit rules loaded).
#
#   sudo bash detections/benign/linux/workload.sh
set -u

WORK="$(mktemp -d /tmp/benign-workload.XXXXXX)"
CTR="benign-workload-sleeper"
NETNS="benign-workload-ns"

log() { printf '[workload] %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# step NAME SECONDS CMD [ARG...]: run CMD with a timeout; never fail.
step() {
  local name="$1" secs="$2"
  shift 2
  if ! have "$1"; then
    log "skip  $name ($1 not installed)"
    return 0
  fi
  log "run   $name"
  timeout --kill-after=5 "$secs" "$@" >/dev/null 2>&1 || log "      $name exited $?"
}

# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  log "cleanup"
  have docker && docker rm -f "$CTR" >/dev/null 2>&1
  have ip && ip netns del "$NETNS" >/dev/null 2>&1
  rm -rf "$WORK"
  return 0
}
trap cleanup EXIT
# A cancelled or timed-out step sends TERM/INT: exit so the EXIT trap cleans up.
trap 'exit 143' TERM INT

# ---- network diagnostics (T1040, T1068 xfrm) ------------------------------
network() {
  if have tcpdump; then
    log "run   tcpdump -c 10 on lo, with ping as traffic"
    timeout 20 tcpdump -i lo -c 10 -nn >/dev/null 2>&1 &
    local tcpdump_pid=$!
    sleep 2
  fi
  step "ping 127.0.0.1" 15 ping -c 3 -i 0.2 127.0.0.1
  step "ping ::1" 15 ping -6 -c 3 -i 0.2 ::1
  if [ -n "${tcpdump_pid:-}" ]; then
    wait "$tcpdump_pid" 2>/dev/null || log "      tcpdump exited $?"
  fi
  step "mtr report to 127.0.0.1" 30 mtr -r -n -c 2 127.0.0.1
  step "tracepath 127.0.0.1" 20 tracepath -n -m 3 127.0.0.1
  local gw dev
  gw="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"
  dev="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  if [ -n "$gw" ] && [ -n "$dev" ]; then
    step "arping the default gateway" 15 arping -c 2 -I "$dev" "$gw"
  fi
  step "ip -s link" 10 ip -s link
  step "ip route" 10 ip route show
  step "ss -tunap" 10 ss -tunap
  step "ip xfrm state list" 10 ip xfrm state list
  step "ip xfrm policy list" 10 ip xfrm policy list
  step "resolvectl status" 10 resolvectl status
  step "getent hosts example.com" 10 getent hosts example.com
  step "curl https://example.com/" 30 curl -sS -o /dev/null https://example.com/
}

# ---- namespaces (T1068 unshare, T1611 setns) ------------------------------
namespaces() {
  step "unshare --net (throwaway netns)" 15 unshare --net -- ip -brief link
  step "unshare --user --map-root-user --net" 15 \
    unshare --user --map-root-user --net -- ip -brief link
  if have ip; then
    step "ip netns add" 10 ip netns add "$NETNS"
    step "ip netns exec ip link" 10 ip netns exec "$NETNS" ip -brief link
    step "ip netns del" 10 ip netns del "$NETNS"
  fi
}

# ---- containers (T1611 setns, T1620 memfd/execveat via runc) --------------
containers() {
  have docker || { log "skip  containers (docker not installed)"; return 0; }
  step "docker run --rm hello-world" 120 docker run --rm hello-world
  step "docker run -d busybox sleep" 120 \
    docker run -d --rm --name "$CTR" busybox:1.36 sleep 120
  step "docker exec true" 30 docker exec "$CTR" true
  step "docker exec ps" 30 docker exec "$CTR" ps
  local pid
  pid="$(docker inspect -f '{{.State.Pid}}' "$CTR" 2>/dev/null || true)"
  if [ -n "$pid" ] && [ "$pid" != "0" ]; then
    step "nsenter -n into the container (debug its network)" 15 \
      nsenter -t "$pid" -n -- ip -brief addr
  fi
  step "docker stats --no-stream" 30 docker stats --no-stream
  step "docker ps" 15 docker ps
  step "docker logs" 15 docker logs "$CTR"
  step "docker rm -f" 30 docker rm -f "$CTR"
}

# ---- debugging and profiling (T1622 ptrace, T1068 perf_event_open) --------
debugging() {
  step "gdb -batch -ex run /bin/true" 60 gdb -batch -nx -ex run --args /bin/true
  step "strace -f /bin/true" 30 strace -f -o /dev/null /bin/true
  step "strace -c ls" 30 strace -c -o /dev/null ls /
  step "perf stat /bin/true" 30 perf stat -e task-clock -- /bin/true
  step "ltrace /bin/true" 30 ltrace -o /dev/null /bin/true
}

# ---- eBPF the host itself loads (T1014) -----------------------------------
ebpf() {
  step "bpftool prog list" 15 bpftool prog list
  step "bpftool map list" 15 bpftool map list
  step "systemd-run -p IPAddressDeny=any" 30 \
    systemd-run --wait --quiet --collect -p IPAddressDeny=any /bin/true
  step "systemd-run -p IPAccounting=yes" 30 \
    systemd-run --wait --quiet --collect -p IPAccounting=yes /bin/true
}

# ---- kernel crypto and keyrings (T1068 AF_ALG, add_key) -------------------
crypto_keys() {
  step "cryptsetup benchmark (AF_ALG)" 90 \
    cryptsetup benchmark --cipher aes-xts-plain64 --key-size 256
  step "keyctl show @s" 10 keyctl show @s
  if have keyctl; then
    log "run   keyctl add + unlink a session key"
    local id
    id="$(timeout 10 keyctl add user benign-workload-key placeholder @s 2>/dev/null || true)"
    [ -n "$id" ] && { timeout 10 keyctl unlink "$id" @s >/dev/null 2>&1 || true; }
  fi
}

# ---- io_uring (T1685) -----------------------------------------------------
io_uring() {
  step "fio --ioengine=io_uring" 60 \
    fio --name=benign-uring --ioengine=io_uring --rw=randread --bs=4k --size=8M \
    --runtime=5 --time_based --filename="$WORK/fio.dat"
  rm -f "$WORK/fio.dat"
}

# ---- developer and package noise (pipes, splice, fork/exec) ---------------
developer() {
  step "apt-get update" 180 apt-get update -qq
  step "apt-cache policy openssl" 30 apt-cache policy openssl
  step "dpkg -l" 30 dpkg -l
  if have python3; then
    step "python3 -m venv" 120 python3 -m venv "$WORK/venv"
    step "pip install (venv)" 180 "$WORK/venv/bin/pip" install --quiet --no-cache-dir six
  fi
  if have git; then
    step "git init + commit" 30 bash -c '
      cd "$1" && git init -q repo && cd repo &&
      printf "hello\n" > README && git add README &&
      git -c user.name=benign -c user.email=benign@example.com commit -q -m init &&
      git log --oneline | cat' _ "$WORK"
  fi
  if have gcc && have make; then
    step "make + gcc a hello program" 60 bash -c '
      cd "$1" &&
      printf "#include <stdio.h>\nint main(void){puts(\"hello\");return 0;}\n" > hello.c &&
      printf "hello: hello.c\n\tgcc -O2 -o hello hello.c\n" > Makefile &&
      make -s && ./hello' _ "$WORK"
  fi
  step "shell pipelines" 30 bash -c '
    head -c 4194304 /dev/urandom > "$1/blob" &&
    cat "$1/blob" | sha256sum | cut -c1-16 &&
    ps aux | grep -c . && ls -la /usr/bin | sort | tail -n 3 &&
    tar -C "$1" -czf "$1/blob.tgz" blob && rm -f "$1/blob" "$1/blob.tgz"' _ "$WORK"
}

# ---- service and host management ------------------------------------------
service() {
  step "systemctl list-units" 30 systemctl list-units --type=service --no-pager
  step "systemctl status ssh" 15 systemctl status ssh --no-pager
  step "journalctl -n 200" 30 journalctl -n 200 --no-pager
  step "logger" 10 logger -t benign-workload "det-eng benign workload running"
  step "timedatectl" 10 timedatectl
  step "hostnamectl" 10 hostnamectl
  step "df -h" 10 df -h
  step "lsblk" 10 lsblk
  step "vmstat" 10 vmstat 1 2
}

main() {
  log "start ($(date -u +%Y-%m-%dT%H:%M:%SZ)) as uid $(id -u), work dir $WORK"
  network
  namespaces
  containers
  debugging
  ebpf
  crypto_keys
  io_uring
  developer
  service
  log "done ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
}

main "$@"
exit 0
