#!/usr/bin/env bash
# Install apt packages on a GitHub runner.
#
#   apt_install.sh [--optional "<package> <package> ..."] <package>...
#
# The packages after the options are necessary: the script fails if one of them is not
# installed. A package of --optional that cannot be installed gives a notice only.
#
# Why this script: the runner image reads the Ubuntu packages from a mirror list
# (/etc/apt/apt-mirrors.txt: azure.archive.ubuntu.com, then archive.ubuntu.com and
# security.ubuntu.com). On 2026-11-11 the resolver of the runners (168.63.129.16) did not
# give these names for more than three hours ("Temporary failure resolving
# 'azure.archive.ubuntu.com'"), and each job that installs auditd failed before its
# first test. Public resolvers gave the same names in that time.
#
# What it does:
#   1. If the resolver of the runner gives the first mirror, it runs apt as the two old
#      lines did (apt-get update, apt-get install -y).
#   2. If the resolver does not give the first mirror, or apt failed with a message about
#      name resolution, apt gets one more run with two public resolvers. Only apt sees
#      them: each apt-get of that run starts in a private mount namespace in which
#      /etc/resolv.conf names the public resolvers. The resolver of the runner is not
#      changed, so there is nothing to put back, also when the job is killed.
#   3. If that private namespace cannot be made, or the public resolvers give no mirror
#      either, and apt had no run yet, apt gets its run with the resolver of the runner
#      (apt goes to the next mirror of its list by itself).
#
# A different resolver cannot make apt install a package that the Ubuntu archive key did
# not sign: apt checks the signature of the package index and the hash of each package.
# It can stop or slow the install.
#
# APT_INSTALL_FORCE_PUBLIC=1 goes to step 2 with no fault. A CI job uses it to prove on a
# runner that the second way works; with it, the script fails if that way cannot be used.
set -euo pipefail
set -f   # the lists hold package names, not file patterns

usage() {
  echo "usage: apt_install.sh [--optional \"<package> ...\"] <package>..." >&2
  exit 2
}

OPTIONAL=""
if [[ "${1:-}" == "--optional" ]]; then
  [[ $# -ge 2 ]] || usage
  OPTIONAL="$2"
  shift 2
fi
[[ $# -gt 0 ]] || usage
# A name goes to apt-get that runs as root: refuse what is not a package name (for
# example a name that starts with "-", which apt-get reads as an option).
# shellcheck disable=SC2086  # the list of optional packages is split on purpose
for name in "$@" $OPTIONAL; do
  if [[ ! "$name" =~ ^[a-z0-9][a-z0-9+.:=~_-]*$ ]]; then
    echo "::error title=apt_install::not a package name: '${name//[^[:print:]]/?}'" >&2
    exit 2
  fi
done

MIRROR_HOSTS=(azure.archive.ubuntu.com archive.ubuntu.com security.ubuntu.com)
PUBLIC_RESOLVERS=(1.1.1.1 8.8.8.8)
RESOLVER_FAULT='Temporary failure resolving|Could not resolve|Temporary failure in name resolution'
FORCE_PUBLIC="${APT_INSTALL_FORCE_PUBLIC:-0}"
RUN=(sudo)        # how each apt-get starts; the second way adds the private namespace
LOG="$(mktemp)"   # the output of apt, to see why it failed
RESOLV=""
trap 'rm -f "$LOG" "$RESOLV"' EXIT

# resolves <runner|apt> <host>...: 0 when the resolver gives one of the hosts. "apt" asks
# as apt-get will run. A resolver that does not answer needs 10 seconds for each host.
resolves() {
  local how="$1" host
  shift
  for host in "$@"; do
    if [[ "$how" == "apt" ]]; then
      if "${RUN[@]}" timeout 10 getent ahosts "$host" >/dev/null 2>&1; then return 0; fi
    else
      if timeout 10 getent ahosts "$host" >/dev/null 2>&1; then return 0; fi
    fi
  done
  return 1
}

apt_logged() { "${RUN[@]}" apt-get "$@" 2>&1 | tee -a "$LOG"; }   # pipefail keeps the status of apt-get

install_all() {
  # Each necessary command has its own `|| return 1`: bash does not stop a function at a
  # failed command when the function is the condition of an `if`.
  # `apt-get update` ends with 0 also when it fetched no index; the install then fails.
  apt_logged update || return 1
  apt_logged install -y -- "$@" || return 1
  local pkg
  # shellcheck disable=SC2086  # the list of optional packages is split on purpose
  if [[ -n "$OPTIONAL" ]] && ! apt_logged install -y -- $OPTIONAL; then
    for pkg in $OPTIONAL; do
      "${RUN[@]}" apt-get install -y -- "$pkg" >/dev/null 2>&1 \
        || echo "::notice title=apt_install::optional package $pkg not installed; a step that needs it will skip"
    done
  fi
  return 0
}

RUNNER_RUN=0      # 1 after apt had a run with the resolver of the runner
if [[ "$FORCE_PUBLIC" == "1" ]]; then
  echo "[apt_install] APT_INSTALL_FORCE_PUBLIC=1: apt runs with the public resolvers, with no fault (a test of that way)"
elif resolves runner "${MIRROR_HOSTS[0]}"; then
  RUNNER_RUN=1
  if install_all "$@"; then
    exit 0
  fi
  if ! grep -qE "$RESOLVER_FAULT" "$LOG" && resolves runner "${MIRROR_HOSTS[0]}"; then
    echo "::error title=apt_install::apt failed, and not because of the resolver: the mirror name resolves and apt gave no message about name resolution. See the E: lines of apt above." >&2
    exit 1
  fi
  echo "::warning title=apt_install::apt could not resolve a mirror with the resolver of the runner. One more run with public resolvers, for apt only."
else
  echo "::warning title=apt_install::the runner cannot resolve ${MIRROR_HOSTS[0]}. apt runs with public resolvers (for apt only)."
fi

RESOLV="$(mktemp)"
printf 'nameserver %s\n' "${PUBLIC_RESOLVERS[@]}" > "$RESOLV"
chmod 0644 "$RESOLV"   # the download methods of apt run as the user _apt
# One private mount namespace for each command; in it /etc/resolv.conf is $RESOLV.
PRIVATE=(sudo unshare --mount -- sh -c 'mount --bind "$0" /etc/resolv.conf && exec "$@"' "$RESOLV")
if "${PRIVATE[@]}" true; then
  RUN=("${PRIVATE[@]}")
  if resolves apt "${MIRROR_HOSTS[@]}"; then
    echo "[apt_install] the public resolvers give a mirror; apt runs with them"
    : > "$LOG"
    if install_all "$@"; then
      exit 0
    fi
    echo "::error title=apt_install::apt failed also with the public resolvers ${PUBLIC_RESOLVERS[*]}. See the E: lines of apt above." >&2
    exit 1
  fi
  echo "::warning title=apt_install::the public resolvers ${PUBLIC_RESOLVERS[*]} give no mirror of the list either."
else
  echo "::warning title=apt_install::cannot give apt a private resolv.conf (unshare or mount failed)."
fi

RUN=(sudo)
if [[ "$FORCE_PUBLIC" == "1" ]]; then
  echo "::error title=apt_install::APT_INSTALL_FORCE_PUBLIC=1, and the way with the public resolvers cannot be used on this runner." >&2
  exit 1
fi
if [[ "$RUNNER_RUN" == "1" ]]; then
  echo "::error title=apt_install::apt failed with the resolver of the runner, and the public resolvers cannot help." >&2
  exit 1
fi
echo "[apt_install] one run with the resolver of the runner: apt can go to the next mirror of its list"
if install_all "$@"; then
  exit 0
fi
echo "::error title=apt_install::apt failed with the resolver of the runner, and the public resolvers cannot help." >&2
exit 1
