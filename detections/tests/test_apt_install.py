"""Tests of .github/scripts/apt_install.sh, the package install step of the CI jobs.

The script runs on a GitHub runner with sudo, apt-get and systemd-resolved. Here each
of these programs is a stub, so the tests need no network and no root. They hold the
logic of the script: when it changes the resolver, that a necessary package that is
not installed fails the step, and that the resolver of the runner is put back.

    python3 -B -m unittest detections.tests.test_apt_install
"""

import os
import stat
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO, ".github", "scripts", "apt_install.sh")

# Each stub reads and writes the directory $STATE:
#   resolver   the resolver in use: "runner" or "public"
#   resolves   the resolvers that give the mirror host (one name on each line)
#   apt_ok     the resolvers with which apt-get install can fetch a package
#   missing    packages that no install can get
#   calls      one line for each call of apt-get and resolvectl
STUBS = {
    "sudo": 'exec "$@"\n',
    "timeout": 'shift\nexec "$@"\n',
    "getent": 'grep -qx "$(cat "$STATE/resolver")" "$STATE/resolves"\n',
    "ip": 'cat "$STATE/route"\n',
    "resolvectl": (
        'echo "resolvectl $*" >> "$STATE/calls"\n'
        'case "$1 $#" in\n'
        '  "dns 2") echo "Link 2 ($2): 168.63.129.16" ;;\n'
        '  dns*) echo public > "$STATE/resolver" ;;\n'
        '  revert*) echo runner > "$STATE/resolver" ;;\n'
        'esac\n'),
    "apt-get": (
        'echo "apt-get $* [$(cat "$STATE/resolver")]" >> "$STATE/calls"\n'
        'if [ "$1" = update ]; then exit 0; fi\n'
        'grep -qx "$(cat "$STATE/resolver")" "$STATE/apt_ok" || exit 100\n'
        'for pkg in "$@"; do if grep -qx -- "$pkg" "$STATE/missing"; then exit 100; fi; done\n'
        'exit 0\n'),
}
ROUTE = "default via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.4 metric 100\n"
PUBLIC = "resolvectl dns eth0 1.1.1.1 8.8.8.8"


class AptInstall(unittest.TestCase):

    def run_script(self, *args, resolves=("runner", "public"), apt_ok=("runner", "public"),
                   missing=(), route=ROUTE):
        with tempfile.TemporaryDirectory(prefix="deteng-apt-") as state:
            bin_dir = os.path.join(state, "bin")
            os.mkdir(bin_dir)
            for name, body in STUBS.items():
                path = os.path.join(bin_dir, name)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("#!/bin/sh\n" + body)
                os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
            for name, text in (("resolver", "runner\n"), ("resolves", "\n".join(resolves) + "\n"),
                               ("apt_ok", "\n".join(apt_ok) + "\n"),
                               ("missing", "\n".join(missing) + "\n"), ("route", route), ("calls", "")):
                with open(os.path.join(state, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            done = subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, timeout=60,
                                  env={"PATH": bin_dir + ":/usr/bin:/bin", "STATE": state}, check=False)
            with open(os.path.join(state, "calls"), encoding="utf-8") as fh:
                done.calls = fh.read().splitlines()
            with open(os.path.join(state, "resolver"), encoding="utf-8") as fh:
                done.resolver = fh.read().strip()
            return done

    def test_a_runner_that_reaches_the_mirror_installs_and_does_not_touch_the_resolver(self):
        done = self.run_script("auditd", "gcc")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.calls, ["apt-get update [runner]", "apt-get install -y auditd gcc [runner]"])

    def test_a_runner_that_cannot_resolve_the_mirror_goes_to_the_public_resolvers_at_once(self):
        # No apt run with the resolver of the runner: one such run takes about five minutes.
        done = self.run_script("auditd", resolves=("public",), apt_ok=("public",))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.calls, ["resolvectl dns eth0", PUBLIC, "resolvectl flush-caches",
                                      "apt-get update [public]", "apt-get install -y auditd [public]",
                                      "resolvectl revert eth0"])
        self.assertIn("cannot resolve azure.archive.ubuntu.com", done.stdout)
        self.assertEqual(done.resolver, "runner", "the resolver of the runner is not put back")

    def test_an_install_that_fails_with_the_resolver_of_the_runner_gets_one_more_try(self):
        done = self.run_script("auditd", apt_ok=("public",))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.calls, ["apt-get update [runner]", "apt-get install -y auditd [runner]",
                                      "resolvectl dns eth0", PUBLIC, "resolvectl flush-caches",
                                      "apt-get update [public]", "apt-get install -y auditd [public]",
                                      "resolvectl revert eth0"])
        self.assertEqual(done.resolver, "runner")

    def test_a_mirror_that_no_resolver_reaches_fails_the_step_and_puts_the_resolver_back(self):
        done = self.run_script("auditd", resolves=(), apt_ok=())
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(done.calls[-2:], ["apt-get install -y auditd [public]", "resolvectl revert eth0"])
        self.assertEqual(done.resolver, "runner")

    def test_a_necessary_package_that_is_not_installed_fails_the_step(self):
        # Also when the optional packages install: their success must not hide it.
        done = self.run_script("--optional", "fio make", "auditd", missing=("auditd",))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertNotIn("apt-get install -y fio make [runner]", done.calls)
        self.assertNotIn("apt-get install -y fio make [public]", done.calls)

    def test_an_optional_package_that_is_not_installed_gives_a_notice_only(self):
        done = self.run_script("--optional", "fio linux-tools-6.8 make", "auditd", missing=("linux-tools-6.8",))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.calls, [
            "apt-get update [runner]", "apt-get install -y auditd [runner]",
            "apt-get install -y fio linux-tools-6.8 make [runner]", "apt-get install -y fio [runner]",
            "apt-get install -y linux-tools-6.8 [runner]", "apt-get install -y make [runner]"])
        self.assertEqual(done.stdout.count("::notice title=apt_install::package"), 1, done.stdout)
        self.assertIn("package linux-tools-6.8 not installed", done.stdout)

    def test_no_package_is_a_usage_error(self):
        for args in ((), ("--optional", "fio")):
            with self.subTest(args=args):
                done = self.run_script(*args)
                self.assertEqual(done.returncode, 2, done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("usage: apt_install.sh", done.stderr)

    def test_no_default_interface_fails_the_step_before_a_change_of_the_resolver(self):
        done = self.run_script("auditd", resolves=(), route="")
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(done.calls, [])
        self.assertIn("found no default network interface", done.stderr)

    def test_each_workflow_installs_packages_through_the_script(self):
        # A new `apt-get install` in a workflow would not have the second try.
        folder = os.path.join(REPO, ".github", "workflows")
        direct, through = [], 0
        for name in sorted(os.listdir(folder)):
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                for number, line in enumerate(fh, 1):
                    code = line.split("#", 1)[0]
                    if "apt-get" in code or "apt install" in code:
                        direct.append("%s:%d" % (name, number))
                    if "bash .github/scripts/apt_install.sh" in code:
                        through += 1
        self.assertEqual(direct, [])
        self.assertGreaterEqual(through, 4)


if __name__ == "__main__":
    unittest.main()
