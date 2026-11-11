"""Tests of .github/scripts/apt_install.sh, the package install step of the CI jobs.

The script runs on a GitHub runner with sudo, apt-get, unshare and getent. Here each of
these programs is a stub, so the tests need no network and no root. They hold the logic
of the script: when apt gets the public resolvers, that only apt gets them, that apt
always gets one run with the resolver of the runner when the other way cannot be used,
and that a necessary package that is not installed fails the step.

The stubs do not show that the private mount namespace works on a runner. The CI job
`apt-install-fallback` (validate-detections.yml) shows that, on each pull request.

    python3 -B -m unittest detections.tests.test_apt_install
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(TESTS))
SCRIPT = os.path.join(REPO, ".github", "scripts", "apt_install.sh")
sys.path.insert(0, TESTS)

# The script sees these real programs and the stubs, and no other program.
REAL = ("bash", "sh", "cat", "grep", "tee", "mktemp", "rm", "chmod", "true")

# Each stub reads and writes the directory $STATE:
#   resolves_runner  the hosts that the resolver of the runner gives (one on each line)
#   resolves_public  the hosts that the public resolvers give
#   apt_ok           the resolvers ("runner", "public") with which apt can fetch
#   missing          packages that no install can get
#   fail             what fails: "unshare" (the program), "update" (apt-get update)
#   calls            one line for each call of getent, apt-get and unshare
# A stub of a program that needs root refuses a call that did not come through sudo.
# `unshare` gives its command the resolver "public", as the private resolv.conf does.
STUBS = {
    "sudo": 'VIA_SUDO=1 exec "$@"\n',
    "timeout": 'echo "$1" >> "$STATE/timeouts"\nshift\nexec "$@"\n',
    "getent": (
        'who="${RESOLVER:-runner}"\n'
        'echo "getent $* [$who]" >> "$STATE/calls"\n'
        '[ "$1" = ahosts ] || exit 2\n'
        'grep -qx -- "$2" "$STATE/resolves_$who"\n'),
    "unshare": (
        '[ -n "${VIA_SUDO:-}" ] || { echo "unshare: not root" >&2; exit 1; }\n'
        'if grep -qx unshare "$STATE/fail"; then echo "unshare: Operation not permitted" >&2; exit 1; fi\n'
        'printf "%s\\n" "$1 $2 $3 $4" > "$STATE/unshare_options"\n'
        'printf "%s\\n" "$5" > "$STATE/unshare_script"\n'
        'cat "$6" > "$STATE/resolv_seen"\n'
        'shift 6\n'
        'echo "unshare: $*" >> "$STATE/calls"\n'
        'RESOLVER=public exec "$@"\n'),
    "apt-get": (
        '[ -n "${VIA_SUDO:-}" ] || { echo "apt-get: not root" >&2; exit 100; }\n'
        'who="${RESOLVER:-runner}"\n'
        'echo "apt-get $* [$who]" >> "$STATE/calls"\n'
        'if [ "$1" = update ]; then\n'
        '  if grep -qx update "$STATE/fail"; then echo "E: The repository is not signed."; exit 100; fi\n'
        '  exit 0\n'
        'fi\n'
        'if ! grep -qx "$who" "$STATE/apt_ok"; then\n'
        '  echo "E: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/x.deb  Temporary failure resolving \'azure.archive.ubuntu.com\'"\n'
        '  exit 100\n'
        'fi\n'
        'for pkg in "$@"; do\n'
        '  if grep -qx -- "$pkg" "$STATE/missing"; then echo "E: Unable to locate package $pkg"; exit 100; fi\n'
        'done\n'
        'exit 0\n'),
}
MIRRORS = ("azure.archive.ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com")
ASK_RUNNER = "getent ahosts azure.archive.ubuntu.com [runner]"
ASK_PUBLIC = "getent ahosts azure.archive.ubuntu.com [public]"


def apt(resolver, *packages):
    return ["apt-get update [%s]" % resolver,
            "apt-get install -y -- %s [%s]" % (" ".join(packages), resolver)]


class AptInstall(unittest.TestCase):

    def run_script(self, *args, runner=MIRRORS, public=MIRRORS, apt_ok=("runner", "public"),
                   missing=(), fail=(), env=None):
        with tempfile.TemporaryDirectory(prefix="deteng-apt-") as state:
            bin_dir, tmp_dir = os.path.join(state, "bin"), os.path.join(state, "tmp")
            os.mkdir(bin_dir)
            os.mkdir(tmp_dir)
            for name in REAL:
                os.symlink(shutil.which(name, path="/usr/bin:/bin"), os.path.join(bin_dir, name))
            for name, body in STUBS.items():
                path = os.path.join(bin_dir, name)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("#!/bin/sh\n" + body)
                os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
            for name, lines in (("resolves_runner", runner), ("resolves_public", public), ("apt_ok", apt_ok),
                                ("missing", missing), ("fail", fail), ("calls", ()), ("timeouts", ())):
                with open(os.path.join(state, name), "w", encoding="utf-8") as fh:
                    fh.write("".join(line + "\n" for line in lines))
            # The working directory holds a file with the name of a package: a list that
            # is read as a file pattern would become that name.
            work = os.path.join(state, "work")
            os.mkdir(work)
            with open(os.path.join(work, "make"), "w", encoding="utf-8"):
                pass
            environment = {"PATH": bin_dir, "STATE": state, "TMPDIR": tmp_dir}
            environment.update(env or {})
            done = subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, timeout=60,
                                  env=environment, cwd=work, check=False)
            done.state = {}
            for name in ("calls", "timeouts", "unshare_options", "unshare_script", "resolv_seen"):
                path = os.path.join(state, name)
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as fh:
                        done.state[name] = fh.read()
            done.calls = done.state["calls"].splitlines()
            done.left = sorted(os.listdir(tmp_dir))
            return done

    def assert_only_apt_had_the_public_resolvers(self, done):
        """The way with the public resolvers: a private mount namespace for each command,
        with a resolv.conf that names the two resolvers. Nothing stays behind."""
        self.assertEqual(done.state["unshare_options"], "--mount -- sh -c\n")
        self.assertEqual(done.state["unshare_script"], 'mount --bind "$0" /etc/resolv.conf && exec "$@"\n')
        self.assertEqual(done.state["resolv_seen"], "nameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        self.assertEqual(done.left, [], "the script left a temporary file")

    def test_a_runner_that_reaches_the_mirror_installs_as_the_two_old_lines_did(self):
        done = self.run_script("auditd", "gcc")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", "auditd", "gcc"))
        self.assertNotIn("::warning", done.stdout)
        self.assertEqual(done.left, [])

    def test_a_runner_that_cannot_resolve_the_mirror_gives_apt_the_public_resolvers_at_once(self):
        # No apt run with the resolver of the runner first: one such run takes about five minutes.
        done = self.run_script("auditd", runner=(), apt_ok=("public",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER, "unshare: true", "unshare: timeout 10 getent ahosts " + MIRRORS[0],
                                      ASK_PUBLIC, "unshare: apt-get update", "apt-get update [public]",
                                      "unshare: apt-get install -y -- auditd", "apt-get install -y -- auditd [public]"])
        self.assertIn("::warning title=apt_install::the runner cannot resolve azure.archive.ubuntu.com", done.stdout)
        self.assert_only_apt_had_the_public_resolvers(done)

    def test_an_install_that_fails_for_the_resolver_gets_one_more_run_with_the_public_resolvers(self):
        done = self.run_script("auditd", apt_ok=("public",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual([c for c in done.calls if c.startswith("apt-get")], apt("runner", "auditd") + apt("public", "auditd"))
        self.assertIn("apt could not resolve a mirror with the resolver of the runner", done.stdout)
        self.assert_only_apt_had_the_public_resolvers(done)

    def test_an_install_that_fails_for_a_different_reason_gets_no_second_run(self):
        done = self.run_script("auditd", "no-such-package", missing=("no-such-package",))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", "auditd", "no-such-package") + [ASK_RUNNER])
        self.assertIn("::error title=apt_install::apt failed, and not because of the resolver", done.stderr)
        self.assertEqual(done.left, [])

    def test_a_namespace_that_cannot_be_made_still_gives_apt_its_run_with_the_resolver_of_the_runner(self):
        # The old two lines work in this condition (apt goes to the next mirror of its list).
        done = self.run_script("auditd", runner=(), fail=("unshare",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", "auditd"))
        self.assertIn("cannot give apt a private resolv.conf", done.stdout)
        self.assertEqual(done.left, [])

    def test_public_resolvers_that_give_no_mirror_still_give_apt_its_run_with_the_resolver_of_the_runner(self):
        done = self.run_script("auditd", runner=(), public=())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual([c for c in done.calls if c.startswith("apt-get")], apt("runner", "auditd"))
        # Each of the three mirror names was asked with the public resolvers.
        self.assertEqual([c for c in done.calls if c.endswith("[public]")],
                         ["getent ahosts %s [public]" % host for host in MIRRORS])
        self.assertIn("give no mirror of the list either", done.stdout)

    def test_one_mirror_from_the_public_resolvers_is_sufficient(self):
        done = self.run_script("auditd", runner=(), public=("archive.ubuntu.com",), apt_ok=("public",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual([c for c in done.calls if c.startswith("apt-get")], apt("public", "auditd"))

    def test_a_mirror_that_no_way_reaches_fails_the_step_after_one_run_for_each_way(self):
        ways = {"the public resolvers give the name, apt cannot fetch": dict(runner=(), apt_ok=()),
                "no resolver gives a name": dict(runner=(), public=(), apt_ok=()),
                "the runner gives the name, no way can fetch": dict(apt_ok=()),
                "apt failed with the runner, and the namespace cannot be made": dict(apt_ok=(), fail=("unshare",)),
                "apt failed with the runner, and the public resolvers give no name": dict(apt_ok=(), public=())}
        for way, state in ways.items():
            with self.subTest(way=way):
                done = self.run_script("auditd", **state)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn("::error title=apt_install::apt failed", done.stderr)
                installs = [c for c in done.calls if c.startswith("apt-get install")]
                self.assertEqual(len(installs), len(set(installs)), "apt had two runs in the same way")
                self.assertEqual(done.left, [])

    def test_an_update_that_fails_stops_before_the_install(self):
        # No install from an index that was not updated.
        done = self.run_script("auditd", fail=("update",))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual([c for c in done.calls if c.startswith("apt-get")], ["apt-get update [runner]"])

    def test_a_necessary_package_that_is_not_installed_fails_the_step(self):
        # Also when the optional packages install: their success must not hide it.
        done = self.run_script("--optional", "fio make", "auditd", missing=("auditd",))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertFalse([c for c in done.calls if "fio" in c], done.calls)

    def test_an_optional_package_that_is_not_installed_gives_a_notice_only(self):
        done = self.run_script("--optional", "fio linux-tools-6.8.0-1017-azure\n   make", "auditd",
                               missing=("linux-tools-6.8.0-1017-azure",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", "auditd") + [
            "apt-get install -y -- fio linux-tools-6.8.0-1017-azure make [runner]", "apt-get install -y -- fio [runner]",
            "apt-get install -y -- linux-tools-6.8.0-1017-azure [runner]", "apt-get install -y -- make [runner]"])
        self.assertEqual(done.stdout.count("::notice title=apt_install::optional package"), 1, done.stdout)
        self.assertIn("optional package linux-tools-6.8.0-1017-azure not installed", done.stdout)

    def test_no_package_is_a_usage_error(self):
        for args in ((), ("--optional",), ("--optional", "fio")):
            with self.subTest(args=args):
                done = self.run_script(*args)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("usage: apt_install.sh", done.stderr)

    def test_a_text_that_is_not_a_package_name_is_refused_before_any_call(self):
        # apt-get runs as root, and it reads a name that starts with "-" as an option.
        bad = (("-oDPkg::Pre-Invoke::=id",), ("auditd", "--allow-unauthenticated"), ("Auditd",), ("a b",),
               ("auditd;id",), ("--optional", "fio -oAPT::Update::Pre-Invoke::=id", "auditd"), ("*",),
               # Not read as a file pattern: the working directory of the test holds the file `make`.
               ("--optional", "*", "auditd"), ("--optional", "mak?", "auditd"))
        for args in bad:
            with self.subTest(args=args):
                done = self.run_script(*args)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("::error title=apt_install::not a package name", done.stderr)

    def test_each_question_to_a_resolver_has_a_limit_of_10_seconds(self):
        done = self.run_script("auditd", runner=(), public=())
        self.assertEqual(set(done.state["timeouts"].split()), {"10"})
        self.assertEqual(len(done.state["timeouts"].split()), 4)     # the runner one time, the public ones three times

    def test_the_forced_way_uses_the_public_resolvers_on_a_runner_with_no_fault(self):
        done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": "1"})
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual([c for c in done.calls if not c.startswith("unshare")], [ASK_PUBLIC] + apt("public", "auditd"))
        self.assert_only_apt_had_the_public_resolvers(done)

    def test_the_forced_way_fails_when_the_public_resolvers_cannot_be_used(self):
        # The CI job that proves this way must not pass through the other way.
        for state in (dict(fail=("unshare",)), dict(public=())):
            with self.subTest(state=state):
                done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": "1"}, **state)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertEqual([c for c in done.calls if c.startswith("apt-get")], [])
                self.assertIn("APT_INSTALL_FORCE_PUBLIC=1, and the way with the public resolvers cannot be used",
                              done.stderr)


class DirectInstalls(unittest.TestCase):
    """No step of a workflow, and no shell script of the repository, runs a package
    manager but through apt_install.sh. The rule reads the parsed `run:` text of each
    step (gatelib.ci_steps), so a folded scalar, a joined line and an alias are read as
    the shell reads them."""

    INSTALLS = re.compile(r"(?<![\w./-])(?:apt-get|apt|aptitude|apt-fast|nala)\s+(?:-\S+\s+)*"
                          r"(?:install|update|upgrade|dist-upgrade|full-upgrade|satisfy|build-dep)\b"
                          r"|(?<![\w./-])dpkg\s+(?:-\S+\s+)*(?:-i|--install)\b"
                          r"|(?<![\w./-])snap\s+install\b")
    CALL = re.compile(r"(?<![\w./-])bash\s+(?:\"?\$\{?GITHUB_WORKSPACE\}?/|\./)?\.github/scripts/apt_install\.sh\"?\s")
    # (workflow, job) of each step that installs packages today.
    USERS = [("detection-quality.yml", "benign-linux-live"),
             ("validate-apiserver-detections.yml", "validate"),
             ("validate-apiserver-detections.yml", "validate-recommended"),
             ("validate-detections.yml", "apt-install-fallback"),
             ("validate-detections.yml", "validate"),
             ("validate-staticpod-detections.yml", "validate")]
    # Shell scripts that may call apt directly, and why.
    ALLOWED = {
        ".github/scripts/apt_install.sh": "the script itself",
        "detections/benign/linux/workload.sh": "`apt-get update -qq` as benign noise, under a timeout, never fatal",
    }

    @classmethod
    def direct(cls, run):
        import gatelib
        return [line for line in gatelib._command_lines(run)
                if cls.INSTALLS.search(re.sub(r"\s+#.*$", "", line))]

    def test_the_rule_finds_a_direct_install(self):
        """CONTROL of the rule, on constructed step texts."""
        found = ["sudo apt-get install -y auditd\n", "sudo apt install -y auditd\n",
                 "sudo apt  install -y auditd\n", "sudo apt -y install auditd\n",
                 "sudo apt \\\n  install -y auditd\n", "sudo apt-get -qq update && sudo apt-get -y upgrade\n",
                 'echo "${x#y}" && sudo apt-get install -y auditd\n', "sudo apt update\n",
                 "sudo dpkg -i ./auditd.deb\n", "sudo snap install yq\n",
                 "if [ $# -eq 0 ]; then sudo apt-get install -y auditd; fi\n"]
        not_found = ["bash .github/scripts/apt_install.sh auditd\n", "# sudo apt-get install -y auditd\ntrue\n",
                     'echo "apt-get is not called here"\n', "apt-cache policy openssl\n",
                     "bash .github/scripts/apt_install.sh auditd  # not apt-get install\n"]
        self.assertEqual([run for run in found + not_found if self.direct(run)], found)

    def test_no_step_installs_packages_directly(self):
        import gatelib
        steps = gatelib.ci_steps()
        users = sorted({(s.workflow, s.job) for s in steps
                        if any(self.CALL.search(line + " ") for line in gatelib._command_lines(s.run))})
        self.assertEqual(users, self.USERS)       # the workflows were read (not vacuous)
        self.assertEqual([(s.workflow, s.job, s.name, line) for s in steps for line in self.direct(s.run)], [])

    def test_no_shell_script_installs_packages_directly(self):
        scripts = []
        for folder, dirs, names in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in (".git", ".kind", "known_bad")]
            scripts += [os.path.relpath(os.path.join(folder, n), REPO).replace(os.sep, "/")
                        for n in names if n.endswith(".sh")]
        self.assertGreater(len(scripts), 10, "the shell scripts were not read")
        direct = []
        for rel in sorted(scripts):
            with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
                if self.direct(fh.read()) and rel not in self.ALLOWED:
                    direct.append(rel)
        self.assertEqual(direct, [])
        self.assertEqual([rel for rel in self.ALLOWED if rel not in scripts], [])


if __name__ == "__main__":
    unittest.main()
