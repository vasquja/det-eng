#!/usr/bin/env bash
# Install apt packages on a GitHub runner.
#
#   apt_install.sh [--optional "<package> <package> ..."] <package>...
#
# The packages after the options are necessary: the script fails if one of them is not
# installed. A package of --optional that cannot be installed gives a notice only.
#
# Why this script: the runner image reads the Ubuntu packages from a mirror list
# (azure.archive.ubuntu.com first, then archive.ubuntu.com and security.ubuntu.com). On
# 2026-11-11 the runners could not resolve these names for more than two hours
# ("Temporary failure resolving 'azure.archive.ubuntu.com'"), and each job that installs
# auditd failed before its first test. A machine outside GitHub resolved the same names
# in that time. So when the resolver of the runner does not give the mirror, or the
# install fails with it, the script gives the default network interface two public
# resolvers, tries one more time, and puts the resolver of the runner back at its end.
#
# apt checks the signature of the package index and the hash of each package, so a
# different resolver cannot give the runner a different package.
set -euo pipefail

OPTIONAL=""
if [[ "${1:-}" == "--optional" ]]; then
  OPTIONAL="${2:-}"
  shift 2
fi
if [[ $# -eq 0 ]]; then
  echo "usage: apt_install.sh [--optional \"<package> ...\"] <package>..." >&2
  exit 2
fi

MIRROR_HOST="azure.archive.ubuntu.com"   # the first host of the mirror list of the runner image
PUBLIC_RESOLVERS=(1.1.1.1 8.8.8.8)
IFACE=""

# A runner that cannot resolve the mirror needs about five minutes for one failed apt
# run. So ask the resolver first, for 10 seconds at most.
resolves() { timeout 10 getent hosts "$MIRROR_HOST" >/dev/null 2>&1; }

install_all() {
  # Each necessary command has its own `|| return 1`: bash does not stop a function at a
  # failed command when the function is the condition of an `if`.
  # `apt-get update` ends with 0 also when it fetched no index; the install then fails.
  sudo apt-get update || return 1
  sudo apt-get install -y "$@" || return 1
  local pkg
  # shellcheck disable=SC2086  # the list of optional packages is split on purpose
  if [[ -n "$OPTIONAL" ]] && ! sudo apt-get install -y $OPTIONAL; then
    for pkg in $OPTIONAL; do
      sudo apt-get install -y "$pkg" >/dev/null 2>&1 \
        || echo "::notice title=apt_install::package $pkg not installed"
    done
  fi
  return 0
}

restore_resolver() {
  if [[ -n "$IFACE" ]]; then
    sudo resolvectl revert "$IFACE" || echo "::warning title=apt_install::could not put the resolver of $IFACE back"
  fi
}

if resolves; then
  if install_all "$@"; then
    exit 0
  fi
  echo "::warning title=apt_install::apt failed with the resolver of the runner. One more try with public resolvers."
else
  echo "::warning title=apt_install::the runner cannot resolve $MIRROR_HOST. Trying with public resolvers."
fi

IFACE="$(ip -o route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
if [[ -z "$IFACE" ]]; then
  echo "::error title=apt_install::found no default network interface, so the resolver cannot be changed" >&2
  exit 1
fi
echo "[apt_install] interface $IFACE; its resolvers now:"
resolvectl dns "$IFACE" || true
trap restore_resolver EXIT
sudo resolvectl dns "$IFACE" "${PUBLIC_RESOLVERS[@]}"
sudo resolvectl flush-caches
if resolves; then
  echo "[apt_install] the public resolvers give $MIRROR_HOST"
else
  echo "[apt_install] the public resolvers do not give $MIRROR_HOST either; apt can still use the next mirror"
fi
install_all "$@"
