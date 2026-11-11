"""Tests of .github/scripts/apt_install.sh, the package install step of the CI jobs.

The script runs on a GitHub runner with sudo, apt-get, unshare, mount and getent. Here
each of these programs is a stub, so the tests need no network and no root. They hold
the logic of the script: when apt gets the public resolvers, that only apt gets them,
that the script fails only after apt failed in a run with the resolver of the runner,
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
#   resolves_runner       the hosts that the resolver of the runner gives (one on each line)
#   resolves_runner_then  if it is there: what the runner gives from its second question on
#   resolves_public       the hosts that the public resolvers give
#   apt_ok                the resolvers ("runner", "public") with which apt can fetch
#   fault                 the text that apt prints when it cannot fetch
#   missing               packages that no install can get
#   fail                  what fails: "unshare", "mount" (the programs), "update" (apt-get
#                         update), "no-index" (an install with no index: "Unable to locate")
#   calls                 one line for each call of getent, apt-get and unshare, and for
#                         each call that the real program would not permit
# The stubs follow the real programs where the script depends on it:
#   - `sudo` starts apt-get and unshare only. Each other command through sudo is a
#     line in `calls` and a failure: the script has no other reason to be root.
#   - `unshare` knows the one form `--mount -- sh -c <text> <file> <command>` and runs
#     that `sh -c` text for real. `mount` works only in that namespace; a command in a
#     namespace with the bind mount gets the answers of the public resolvers.
#   - apt-get prints its messages on stderr, and `apt-get update` ends with 0 when it
#     fetched no index (it prints a W: line). An update prints the line of the local
#     mirror list (`Get:1 file:...`), and a `Hit:` line for a source that it reached.
IN_THE_NAMESPACE = 'who=runner\n[ -n "${IN_NAMESPACE:-}" ] && [ -e "$STATE/mounted.$IN_NAMESPACE" ] && who=public\n'
STUBS = {
    "sudo": r'''
case "$1" in apt-get|unshare) ;; *) echo "sudo $*" >> "$STATE/calls"; exit 1 ;; esac
VIA_SUDO=1 exec "$@"
''',
    "timeout": r'''
echo "$1" >> "$STATE/timeouts"
shift
exec "$@"
''',
    "getent": IN_THE_NAMESPACE + r'''
echo "getent $* [$who]" >> "$STATE/calls"
[ "$1" = ahosts ] || exit 2
list="$STATE/resolves_$who"
if [ "$who" = runner ] && [ -e "$STATE/resolves_runner_then" ]; then
  [ -e "$STATE/runner_asked" ] && list="$STATE/resolves_runner_then"
  : > "$STATE/runner_asked"
fi
grep -qx -- "$2" "$list"
''',
    "unshare": r'''
[ -n "${VIA_SUDO:-}" ] || { echo "unshare: not root" >&2; exit 1; }
if grep -qx unshare "$STATE/fail"; then echo "unshare: unshare failed: Operation not permitted" >&2; exit 1; fi
if [ "$1 $2 $3 $4" != "--mount -- sh -c" ]; then
  echo "unshare $1 $2 $3 $4: not the private mount namespace of the script" >> "$STATE/calls"
  exit 1
fi
shift 2
a="$1" b="$2" c="$3" d="$4"
shift 4
echo "unshare: $*" >> "$STATE/calls"
rm -f "$STATE/mounted.$$"
IN_NAMESPACE=$$ exec "$a" "$b" "$c" "$d" "$@"
''',
    "mount": r'''
if [ -z "${VIA_SUDO:-}" ] || [ -z "${IN_NAMESPACE:-}" ]; then
  echo "mount $* (not in a private namespace)" >> "$STATE/calls"
  exit 1
fi
if grep -qx mount "$STATE/fail"; then echo "mount: /etc/resolv.conf: permission denied" >&2; exit 32; fi
if [ $# -ne 3 ] || [ "$1" != "--bind" ] || [ "$3" != "/etc/resolv.conf" ]; then
  echo "mount $*" >> "$STATE/calls"
  exit 1
fi
cat "$2" > "$STATE/resolv_seen" || exit 32
/bin/ln -f "$2" "$STATE/resolv_link" || exit 32
: > "$STATE/mounted.$IN_NAMESPACE"
''',
    "apt-get": '[ -n "${VIA_SUDO:-}" ] || { echo "apt-get: not root" >&2; exit 100; }\n' + IN_THE_NAMESPACE + r'''
echo "apt-get $* [$who]" >> "$STATE/calls"
fault="$(cat "$STATE/fault")"
if [ "$1" = update ]; then
  if grep -qx update "$STATE/fail"; then echo "E: The repository is not signed." >&2; exit 100; fi
  echo "Get:1 file:/etc/apt/apt-mirrors.txt Mirrorlist [144 B]"
  if grep -qx "$who" "$STATE/apt_ok"; then
    echo "Hit:2 http://azure.archive.ubuntu.com/ubuntu noble InRelease"
  else
    echo "W: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/dists/noble/InRelease  $fault" >&2
  fi
  exit 0
fi
if ! grep -qx "$who" "$STATE/apt_ok"; then
  if grep -qx no-index "$STATE/fail"; then
    echo "E: Unable to locate package $4" >&2
  else
    echo "E: Failed to fetch http://azure.archive.ubuntu.com/ubuntu/pool/x.deb  $fault" >&2
  fi
  exit 100
fi
for pkg in "$@"; do
  if grep -qx -- "$pkg" "$STATE/missing"; then echo "E: Unable to locate package $pkg" >&2; exit 100; fi
done
exit 0
''',
}
MIRRORS = ("azure.archive.ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com")
ASK_RUNNER = "getent ahosts azure.archive.ubuntu.com [runner]"
ASK_PUBLIC = "getent ahosts azure.archive.ubuntu.com [public]"
# The messages of apt for a name that it could not resolve (apt 2.8, methods/connect.cc).
RESOLVER_FAULTS = ("Temporary failure resolving 'azure.archive.ubuntu.com'",
                   "Could not resolve 'azure.archive.ubuntu.com'",
                   "System error resolving 'azure.archive.ubuntu.com:80'",
                   "Something wicked happened resolving 'azure.archive.ubuntu.com:80' (-5 - No address associated with hostname)")
NO_RESOLVER_FAULT = "Connection failed [IP: 192.0.2.10 80]"


def apt(resolver, *packages):
    return ["apt-get update [%s]" % resolver,
            "apt-get install -y -- %s [%s]" % (" ".join(packages), resolver)]


def apt_calls(done):
    return [c for c in done.calls if c.startswith("apt-get")]


class AptInstall(unittest.TestCase):

    def run_script(self, *args, runner=MIRRORS, runner_then=None, public=MIRRORS, apt_ok=("runner", "public"),
                   fault=RESOLVER_FAULTS[0], missing=(), fail=(), env=None):
        with tempfile.TemporaryDirectory(prefix="deteng-apt-") as state:
            bin_dir, tmp_dir = os.path.join(state, "bin"), os.path.join(state, "tmp")
            os.mkdir(bin_dir)
            os.mkdir(tmp_dir)
            for name in REAL:
                os.symlink(shutil.which(name, path="/usr/bin:/bin"), os.path.join(bin_dir, name))
            for name, body in STUBS.items():
                path = os.path.join(bin_dir, name)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("#!/bin/sh\n" + body.lstrip("\n"))
                os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
            files = [("resolves_runner", runner), ("resolves_public", public), ("apt_ok", apt_ok), ("fault", (fault,)),
                     ("missing", missing), ("fail", fail), ("calls", ()), ("timeouts", ())]
            if runner_then is not None:
                files.append(("resolves_runner_then", runner_then))
            for name, lines in files:
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
            for name in ("calls", "timeouts", "resolv_seen"):
                path = os.path.join(state, name)
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as fh:
                        done.state[name] = fh.read()
            link = os.path.join(state, "resolv_link")
            if os.path.exists(link):
                done.state["resolv_mode"] = stat.S_IMODE(os.stat(link).st_mode)
            done.calls = done.state["calls"].splitlines()
            # In each run: the script leaves no temporary file, and writes nothing into
            # the working directory.
            self.assertEqual(sorted(os.listdir(tmp_dir)), [], "the script left a temporary file")
            self.assertEqual(sorted(os.listdir(work)), ["make"], "the script wrote into the working directory")
            return done

    def assert_only_apt_had_the_public_resolvers(self, done, resolvers=("1.1.1.1", "8.8.8.8")):
        """The way with the public resolvers: the bind mount in the private namespace got a
        resolv.conf that names the resolvers, and that each user can read (the methods of
        apt that fetch run as the user _apt). Nothing stays behind."""
        self.assertEqual(done.state["resolv_seen"], "".join("nameserver %s\n" % r for r in resolvers))
        self.assertEqual(done.state["resolv_mode"], 0o644)

    def test_a_runner_that_reaches_the_mirror_installs_as_the_two_old_lines_did(self):
        done = self.run_script("auditd", "gcc")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", "auditd", "gcc"))
        self.assertNotIn("::warning", done.stdout)
        self.assertNotIn("resolv_seen", done.state)      # no mount at all

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
        # apt prints the message on stderr: the script must read stderr too.
        for fault in RESOLVER_FAULTS:
            with self.subTest(fault=fault):
                done = self.run_script("auditd", apt_ok=("public",), fault=fault)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(apt_calls(done), apt("runner", "auditd") + apt("public", "auditd"))
                self.assertEqual([c for c in done.calls if c.startswith("getent") and c.endswith("[runner]")], [ASK_RUNNER])
                self.assertIn("apt could not resolve a mirror with the resolver of the runner", done.stdout)
                self.assertIn(fault, done.stdout)        # the step log shows the message of apt
                self.assert_only_apt_had_the_public_resolvers(done)

    def test_an_update_that_names_the_resolver_fault_is_evidence_also_when_the_install_does_not_name_it(self):
        # What the fault of 2026-11-11 did: `apt-get update` fetched no index and ended with
        # 0, and the install then failed with "Unable to locate package".
        done = self.run_script("auditd", apt_ok=("public",), fail=("no-index",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), apt("runner", "auditd") + apt("public", "auditd"))

    def test_an_install_that_fails_for_a_different_reason_gets_no_second_run(self):
        states = {"a package that does not exist": (("auditd", "no-such-package"), dict(missing=("no-such-package",)),
                                                    "E: Unable to locate package no-such-package"),
                  "a mirror that does not answer": (("auditd",), dict(apt_ok=(), fault=NO_RESOLVER_FAULT), NO_RESOLVER_FAULT)}
        for name, (packages, state, message) in states.items():
            with self.subTest(state=name):
                done = self.run_script(*packages, **state)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", *packages) + [ASK_RUNNER])
                self.assertIn("::error title=apt_install::apt failed, and not because of the resolver", done.stderr)
                self.assertIn(message, done.stdout)

    def test_a_runner_that_lost_the_mirror_in_the_failed_run_gets_the_public_resolvers(self):
        # apt gave no message about name resolution, but the second question to the
        # resolver of the runner (the first mirror only) has no answer.
        for then in ((), ("archive.ubuntu.com", "security.ubuntu.com")):
            with self.subTest(runner_then=then):
                done = self.run_script("auditd", apt_ok=("public",), fault=NO_RESOLVER_FAULT, runner_then=then)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(apt_calls(done), apt("runner", "auditd") + apt("public", "auditd"))
                self.assertEqual([c for c in done.calls if c.startswith("getent") and c.endswith("[runner]")],
                                 [ASK_RUNNER, ASK_RUNNER])

    def test_a_namespace_that_cannot_be_made_still_gives_apt_its_run_with_the_resolver_of_the_runner(self):
        # The old two lines work in this condition (apt goes to the next mirror of its list).
        for what, before_apt in (("unshare", [ASK_RUNNER]), ("mount", [ASK_RUNNER, "unshare: true"])):
            with self.subTest(fails=what):
                done = self.run_script("auditd", runner=(), fail=(what,))
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.calls, before_apt + apt("runner", "auditd"))
                self.assertIn("cannot give apt a private resolv.conf", done.stdout)

    def test_public_resolvers_that_give_no_mirror_still_give_apt_its_run_with_the_resolver_of_the_runner(self):
        done = self.run_script("auditd", runner=(), public=())
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), apt("runner", "auditd"))
        # Each of the three mirror names was asked with the public resolvers.
        self.assertEqual([c for c in done.calls if c.endswith("[public]")],
                         ["getent ahosts %s [public]" % host for host in MIRRORS])
        self.assertIn("give no mirror of the list either", done.stdout)

    def test_one_mirror_from_the_public_resolvers_is_sufficient(self):
        done = self.run_script("auditd", runner=(), public=("archive.ubuntu.com",), apt_ok=("public",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), apt("public", "auditd"))

    def test_apt_that_fails_with_the_public_resolvers_still_gets_its_run_with_the_resolver_of_the_runner(self):
        # The runner does not give the first mirror, and apt cannot fetch with the public
        # resolvers. The old two lines pass here (the next mirror), so the script must too.
        done = self.run_script("auditd", runner=(), apt_ok=("runner",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(done.calls, [ASK_RUNNER, "unshare: true", "unshare: timeout 10 getent ahosts " + MIRRORS[0],
                                      ASK_PUBLIC, "unshare: apt-get update", "apt-get update [public]",
                                      "unshare: apt-get install -y -- auditd", "apt-get install -y -- auditd [public]",
                                      "apt-get update [runner]", "apt-get install -y -- auditd [runner]"])
        self.assertIn("::warning title=apt_install::apt failed also with the public resolvers", done.stdout)

    def test_the_last_run_with_the_resolver_of_the_runner_installs_the_optional_packages_too(self):
        # The job benign-linux-live gives optional packages. Each way to the last run.
        optional = ["apt-get install -y -- fio nosuch make [runner]", "apt-get install -y -- fio [runner]",
                    "apt-get install -y -- nosuch [runner]", "apt-get install -y -- make [runner]"]
        for state in (dict(fail=("unshare",)), dict(fail=("mount",)), dict(public=()), dict(apt_ok=("runner",))):
            with self.subTest(state=state):
                done = self.run_script("--optional", "fio nosuch make", "auditd", runner=(), missing=("nosuch",), **state)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(apt_calls(done)[-6:], apt("runner", "auditd") + optional)
                self.assertEqual(done.stdout.count("::notice title=apt_install::optional package"), 1, done.stdout)

    def test_a_mirror_that_no_way_reaches_fails_the_step_after_one_run_for_each_way(self):
        runner, public = apt("runner", "auditd"), apt("public", "auditd")
        ways = {"the public resolvers give the name, apt cannot fetch": (dict(runner=(), apt_ok=()), public + runner),
                "no resolver gives a name": (dict(runner=(), public=(), apt_ok=()), runner),
                "the runner gives the name, no way can fetch": (dict(apt_ok=()), runner + public),
                "apt failed with the runner, and unshare fails": (dict(apt_ok=(), fail=("unshare",)), runner),
                "apt failed with the runner, and mount fails": (dict(apt_ok=(), fail=("mount",)), runner),
                "apt failed with the runner, and the public resolvers give no name": (dict(apt_ok=(), public=()), runner)}
        for way, (state, runs) in ways.items():
            with self.subTest(way=way):
                done = self.run_script("auditd", **state)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn("::error title=apt_install::apt failed with the resolver of the runner", done.stderr)
                self.assertEqual(apt_calls(done), runs)

    def test_an_update_that_fails_stops_before_the_install(self):
        # No install from an index that was not updated.
        done = self.run_script("auditd", fail=("update",))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), ["apt-get update [runner]"])

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

    def test_the_optional_packages_stay_in_the_namespace_in_the_second_way(self):
        done = self.run_script("--optional", "fio nosuch make", "auditd", runner=(), apt_ok=("public",), missing=("nosuch",))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), apt("public", "auditd") + [
            "apt-get install -y -- fio nosuch make [public]", "apt-get install -y -- fio [public]",
            "apt-get install -y -- nosuch [public]", "apt-get install -y -- make [public]"])
        self.assertEqual(done.stdout.count("::notice title=apt_install::optional package"), 1, done.stdout)
        self.assertIn("optional package nosuch not installed", done.stdout)

    def test_no_package_is_a_usage_error(self):
        for args in ((), ("--optional",), ("--optional", "fio")):
            with self.subTest(args=args):
                done = self.run_script(*args)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("usage: apt_install.sh", done.stderr)

    def test_a_text_that_is_not_a_package_name_is_refused_before_any_call(self):
        # apt-get runs as root. It reads a name that starts with "-" as an option, and a
        # name that ends with "-" as "remove this package" (and then ends with 0).
        bad = (("-oDPkg::Pre-Invoke::=id",), ("auditd", "--allow-unauthenticated"), ("Auditd",), ("a b",),
               ("auditd;id",), ("--optional", "fio -oAPT::Update::Pre-Invoke::=id", "auditd"), ("*",),
               ("auditd-",), ("gcc", "auditd-"), ("--optional", "fio-", "auditd"), ("gcc=1.0-",),
               # apt-get reads `*` as a file pattern and `~i` as a pattern of its own.
               ("lib*",), ("--optional", "fio lib*", "auditd"), ("~i",), ("~nauditd",), ("+x",), (".x",), ("=x",),
               (":x",), ("_x",),
               # The text goes to the log of the step in one line: no second line that the runner reads as a
               # command, also when the text has more than one control character.
               ("x\n::error title=planted::y",), ("x\ny\n::error title=planted::z",), ("x\x1b[31m\x1b[0m",),
               # Not read as a file pattern: the working directory of the test holds the file `make`.
               ("--optional", "*", "auditd"), ("--optional", "mak?", "auditd"))
        for args in bad:
            with self.subTest(args=args):
                done = self.run_script(*args)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("::error title=apt_install::not a package name", done.stderr)
                self.assertEqual(len(done.stderr.splitlines()), 1, done.stderr)
                self.assertNotIn("\x1b", done.stderr)
        # Names that end with "+" are package names (g++, libstdc++).
        done = self.run_script("g++", "libstdc++-14-dev", "python3.12", "gcc=4:13.2.0-7ubuntu1", "libc6:amd64")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_each_question_to_a_resolver_has_a_limit_of_10_seconds(self):
        done = self.run_script("auditd", runner=(), public=())
        self.assertEqual(set(done.state["timeouts"].split()), {"10"})
        self.assertEqual(len(done.state["timeouts"].split()), 4)     # the runner one time, the public ones three times

    def test_the_forced_way_uses_the_public_resolvers_on_a_runner_with_no_fault(self):
        done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": "1"})
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual([c for c in done.calls if not c.startswith("unshare")], [ASK_PUBLIC] + apt("public", "auditd"))
        self.assert_only_apt_had_the_public_resolvers(done)
        # The forced step of the CI job `apt-install-fallback` reads the output of the
        # script: the line of the second way, and a line of apt for a source on the network.
        import gatelib
        forced = [s.run for s in gatelib.ci_steps()
                  if (s.workflow, s.job) == ("validate-detections.yml", "apt-install-fallback") and "CONTROL" not in s.name]
        self.assertEqual(len(forced), 1)
        step = "\n".join(gatelib._command_lines(forced[0]))
        for text in ("APT_INSTALL_FORCE_PUBLIC=1 bash .github/scripts/apt_install.sh auditd 2>&1 | tee /tmp/apt-forced.out",
                     "grep -q 'the public resolvers give a mirror; apt runs with them' /tmp/apt-forced.out",
                     "dpkg -s auditd >/dev/null", 'if [[ "$before" != "$after" ]]; then'):
            self.assertIn(text, step)
        self.assertIn("[apt_install] the public resolvers give a mirror; apt runs with them", done.stdout)
        fetched = re.search(r"if ! grep -Eq '([^']+)' /tmp/apt-forced\.out; then", step)
        self.assertTrue(fetched, step)
        fetched = re.compile(fetched.group(1), re.M)
        self.assertRegex(done.stdout, fetched)
        # An update that reached no source prints the line of the local mirror list only.
        no_source = self.run_script("auditd", apt_ok=(), fail=("no-index",), env={"APT_INSTALL_FORCE_PUBLIC": "1"})
        self.assertIn("Get:1 file:/etc/apt/apt-mirrors.txt", no_source.stdout)
        self.assertNotRegex(no_source.stdout, fetched)

    def test_other_resolvers_can_be_given_and_a_text_that_is_not_an_address_is_refused(self):
        other = ("192.0.2.53", "9.9.9.9")
        # An empty value is "not set": a workflow gives it when its variable has no value.
        for text, resolvers in (("192.0.2.53  9.9.9.9", other), ("192.0.2.53\n9.9.9.9\n", other),
                                ("", ("1.1.1.1", "8.8.8.8"))):
            with self.subTest(resolvers=text):
                done = self.run_script("auditd", runner=(), env={"APT_INSTALL_RESOLVERS": text})
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assert_only_apt_had_the_public_resolvers(done, resolvers=resolvers)
        for text in ("dns.example.com", "1.1.1.1;id", "1.1.1.1 options", " ", "\n", "-o", "1.1.1", "1.1.1.1.1",
                     "1111.1.1.1", "1x1y1z1", "1.1.1.1\nnot-an-address", "1.1.1.1 x\x1by\x1bz\r::error", "1.1.1.1 *"):
            with self.subTest(resolvers=text):
                done = self.run_script("auditd", env={"APT_INSTALL_RESOLVERS": text})
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("APT_INSTALL_RESOLVERS", done.stderr)
                self.assertEqual(len(done.stderr.splitlines()), 1, done.stderr)
                self.assertNotIn("\x1b", done.stderr)

    def test_the_force_value_is_0_or_1(self):
        # A value such as "true" must not give the normal way with no word: the CI job
        # that proves the second way would then prove nothing.
        for value in ("true", "yes", "2", "01", " 1", "1\n1", "1\n1\n::error title=planted::z"):
            with self.subTest(value=value):
                done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": value})
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertEqual(done.calls, [])
                self.assertIn("APT_INSTALL_FORCE_PUBLIC must be 0 or 1", done.stderr)
                self.assertEqual(len(done.stderr.splitlines()), 1, done.stderr)
        for value in ("0", ""):
            with self.subTest(value=value):
                done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": value})
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.calls, [ASK_RUNNER] + apt("runner", "auditd"))

    def test_the_forced_way_fails_when_the_public_resolvers_cannot_be_used(self):
        # The CI job that proves this way must not pass through the other way.
        for state in (dict(fail=("unshare",)), dict(fail=("mount",)), dict(public=())):
            with self.subTest(state=state):
                done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": "1"}, **state)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertEqual(apt_calls(done), [])
                self.assertIn("APT_INSTALL_FORCE_PUBLIC=1, and the way with the public resolvers cannot be used",
                              done.stderr)
        done = self.run_script("auditd", env={"APT_INSTALL_FORCE_PUBLIC": "1"}, apt_ok=("runner",))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), apt("public", "auditd"))
        self.assertIn("APT_INSTALL_FORCE_PUBLIC=1, and apt failed with the public resolvers", done.stderr)

    def test_the_control_of_the_ci_job_fails_with_the_two_texts_that_the_job_looks_for(self):
        # The CONTROL step of `apt-install-fallback`: the forced way, with a resolver that
        # does not answer. The step reads the two texts in the output of the script.
        done = self.run_script("auditd", public=(), env={"APT_INSTALL_FORCE_PUBLIC": "1", "APT_INSTALL_RESOLVERS": "192.0.2.53"})
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertEqual(apt_calls(done), [])
        output = done.stdout + done.stderr
        self.assertIn("give no mirror of the list either", output)
        self.assertIn("the way with the public resolvers cannot be used", output)
        self.assertEqual(done.state["resolv_seen"], "nameserver 192.0.2.53\n")
        import gatelib
        control = [s.run for s in gatelib.ci_steps()
                   if (s.workflow, s.job) == ("validate-detections.yml", "apt-install-fallback") and "CONTROL" in s.name]
        self.assertEqual(len(control), 1)
        for text in ("APT_INSTALL_FORCE_PUBLIC=1 APT_INSTALL_RESOLVERS=192.0.2.53", "grep -q 'give no mirror of the list either'",
                     "grep -q 'the way with the public resolvers cannot be used'"):
            self.assertIn(text, " ".join(gatelib._command_lines(control[0])))


class DirectInstalls(unittest.TestCase):
    """No workflow, composite action or shell script of the repository runs a package
    manager in a usual form but through apt_install.sh.

    The rule reads the parsed `run:` text of each step (gatelib.ci_steps), so a folded
    scalar, a joined line and an alias are read as the shell reads them. It also reads
    each line of each workflow and action file as text, which finds a command in a
    `with:` or `env:` value and in the `run:` of a composite action. Shell scripts are
    the files with the name *.sh and the files with a shell on their first line.

    It is a rule on text. It does not see a command that is built at run time
    (`$TOOL install`), or one that a different program starts (a Python subprocess)."""

    SKIP = r"(?:[^\s;|&]+\s+)*?"         # options, option values and variables before the subcommand
    START = r"(?<![\w.-])(?:/\S*/)?[\"']?"
    INSTALLS = re.compile(
        START + r"(?:apt-get|apt|aptitude|apt-fast|nala)[\"']?\s+" + SKIP
        + r"(?:install|reinstall|update|upgrade|dist-upgrade|full-upgrade|satisfy|build-dep)(?![\w-])"
        + "|" + START + r"dpkg[\"']?\s+" + SKIP + r"(?:-i|--install)(?![\w-])"
        + "|" + START + r"snap[\"']?\s+" + SKIP + r"install(?![\w-])")
    CALL = re.compile(r"(?<![\w./-])bash\s+(?:\"?\$\{?GITHUB_WORKSPACE\}?/|\./)?\.github/scripts/apt_install\.sh\"?\s")
    SHELL_FIRST_LINE = re.compile(rb"^#![^\n]*\b(?:ba|da|z|k)?sh\b")
    # (workflow, job) of each step that installs packages today.
    USERS = [("detection-quality.yml", "benign-linux-live"),
             ("validate-apiserver-detections.yml", "validate"),
             ("validate-apiserver-detections.yml", "validate-recommended"),
             ("validate-detections.yml", "apt-install-fallback"),
             ("validate-detections.yml", "validate"),
             ("validate-staticpod-detections.yml", "validate")]
    THE_SCRIPT = ".github/scripts/apt_install.sh"
    # The lines of other shell scripts that may call apt directly, and why.
    ALLOWED = {
        "detections/benign/linux/workload.sh": {
            'step "apt-get update" 180 apt-get update -qq': "benign noise for the corpus, under a timeout, never fatal",
        },
    }

    @staticmethod
    def no_comment(line):
        """The line with no comment: a `#` starts one only outside of quotes and after
        white space (or as the first character)."""
        quote, escaped = "", False
        for i, char in enumerate(line):
            if escaped:
                escaped = False
            elif char == "\\" and quote != "'":
                escaped = True
            elif quote:
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == "#" and (i == 0 or line[i - 1].isspace()):
                return line[:i]
        return line

    @classmethod
    def direct(cls, run):
        import gatelib
        return [line for line in gatelib._command_lines(run) if cls.INSTALLS.search(cls.no_comment(line))]

    @classmethod
    def workflow_hits(cls, root=REPO):
        """(file, line) of each direct install in a workflow or a composite action."""
        import glob
        import gatelib
        hits = {(".github/workflows/" + s.workflow, line) for s in gatelib.ci_steps(root=root) for line in cls.direct(s.run)}
        files = glob.glob(os.path.join(root, ".github", "workflows", "*.y*ml"))
        files += glob.glob(os.path.join(root, ".github", "actions", "**", "*.y*ml"), recursive=True)
        for path in files:
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    line = " ".join(raw.split())
                    if not line.startswith("#") and cls.INSTALLS.search(cls.no_comment(line)):
                        hits.add((rel, line))
        return sorted(hits)

    @classmethod
    def shell_scripts(cls, root=REPO):
        scripts = []
        for folder, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", ".kind", "known_bad")]
            for name in names:
                path = os.path.join(folder, name)
                if not name.endswith(".sh"):
                    try:
                        with open(path, "rb") as fh:
                            if not cls.SHELL_FIRST_LINE.match(fh.read(120)):
                                continue
                    except OSError:
                        continue
                scripts.append(os.path.relpath(path, root).replace(os.sep, "/"))
        return sorted(scripts)

    @classmethod
    def script_hits(cls, root=REPO):
        """{script: the lines with a direct install}, for each shell script but apt_install.sh."""
        hits = {}
        for rel in cls.shell_scripts(root):
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
                lines = cls.direct(fh.read())
            if lines and rel != cls.THE_SCRIPT:
                hits[rel] = sorted(lines)
        return hits

    def test_the_rule_finds_a_direct_install(self):
        """CONTROL of the rule, on constructed step texts."""
        found = ["sudo apt-get install -y auditd\n", "sudo apt install -y auditd\n",
                 "sudo apt  install -y auditd\n", "sudo apt -y install auditd\n",
                 "sudo apt \\\n  install -y auditd\n", "sudo apt-get -qq update && sudo apt-get -y upgrade\n",
                 'echo "${x#y}" && sudo apt-get install -y auditd\n', "sudo apt update\n",
                 "sudo dpkg -i ./auditd.deb\n", "sudo snap install yq\n",
                 "if [ $# -eq 0 ]; then sudo apt-get install -y auditd; fi\n",
                 # An option with its value as a second word, a variable, a path, quotes.
                 "sudo apt-get -o Acquire::Retries=3 install -y auditd\n", "sudo apt-get -o DPkg::Lock::Timeout=60 update\n",
                 "sudo apt-get -t noble-backports install -y auditd\n", "sudo apt-get $APT_OPTS install -y auditd\n",
                 "sudo /usr/bin/apt-get install -y auditd\n", 'sudo "apt-get" install -y auditd\n',
                 "sudo apt-get reinstall -y auditd\n", "sudo dpkg --force-all -i ./auditd.deb\n",
                 # A `#` in quotes is not a comment.
                 'echo "step #1" && sudo apt-get install -y auditd\n', "echo 'a #b' ; sudo apt-get update\n"]
        not_found = ["bash .github/scripts/apt_install.sh auditd\n", "# sudo apt-get install -y auditd\ntrue\n",
                     'echo "apt-get is not called here"\n', "apt-cache policy openssl\n",
                     "bash .github/scripts/apt_install.sh auditd  # not apt-get install\n",
                     "sudo apt-get remove -y man-db update-notifier\n", "sudo apt-get clean; ls install\n",
                     "dpkg -s auditd >/dev/null\n", "dpkg-query -W -f='${Status}' auditd\n"]
        self.assertEqual([run for run in found + not_found if self.direct(run)], found)

    def test_the_rule_reads_each_place_where_a_command_can_be(self):
        """CONTROL of the places, on a constructed tree: a `with:` value, an `env:` value,
        a composite action, and a shell script with no .sh in its name."""
        files = {
            ".github/workflows/a.yml": (
                "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: example/retry@v3\n        with:\n"
                "          command: sudo apt-get update && sudo apt-get install -y auditd\n"
                "      - run: ${{ env.INSTALL }}\n        env:\n          INSTALL: sudo apt-get install -y gcc\n"
                "      - run: |\n          # sudo apt-get install -y nothing\n          bash .github/scripts/apt_install.sh auditd\n"),
            ".github/actions/tools/action.yml": (
                "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: sudo apt-get install -y jq\n"),
            ".github/scripts/apt_install.sh": "#!/usr/bin/env bash\nsudo apt-get install -y -- \"$@\"\n",
            "tools/setup-runner": "#!/usr/bin/env bash\nsudo apt-get install -y auditd\n",
            "tools/clean.sh": "#!/bin/sh\nrm -rf build\n",
            "tools/report.py": "#!/usr/bin/env python3\nprint('sudo apt-get install -y auditd')\n",
        }
        with tempfile.TemporaryDirectory(prefix="deteng-direct-") as root:
            for rel, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
                with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                    fh.write(text)
            self.assertEqual(self.workflow_hits(root), [
                (".github/actions/tools/action.yml", "run: sudo apt-get install -y jq"),
                (".github/workflows/a.yml", "INSTALL: sudo apt-get install -y gcc"),
                (".github/workflows/a.yml", "command: sudo apt-get update && sudo apt-get install -y auditd")])
            self.assertEqual(self.shell_scripts(root), [".github/scripts/apt_install.sh", "tools/clean.sh", "tools/setup-runner"])
            self.assertEqual(self.script_hits(root), {"tools/setup-runner": ["sudo apt-get install -y auditd"]})

    def test_no_workflow_installs_packages_directly(self):
        import gatelib
        steps = gatelib.ci_steps()
        users = sorted({(s.workflow, s.job) for s in steps
                        if any(self.CALL.search(line + " ") for line in gatelib._command_lines(s.run))})
        self.assertEqual(users, self.USERS)       # the workflows were read (not vacuous)
        self.assertEqual(self.workflow_hits(), [])

    def test_no_shell_script_installs_packages_directly(self):
        scripts = self.shell_scripts()
        self.assertGreater(len(scripts), 10, "the shell scripts were not read")
        self.assertIn(self.THE_SCRIPT, scripts)
        # The rule finds the apt-get lines of the script itself (not vacuous).
        with open(os.path.join(REPO, self.THE_SCRIPT), encoding="utf-8") as fh:
            own = self.direct(fh.read())
        self.assertTrue([line for line in own if line.startswith('"${RUN[@]}" apt-get install -y -- "$pkg"')], own)
        # Each direct line is one that ALLOWED names, and each line of ALLOWED is there.
        self.assertEqual(self.script_hits(), {rel: sorted(lines) for rel, lines in self.ALLOWED.items()})


if __name__ == "__main__":
    unittest.main()
