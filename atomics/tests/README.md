# Tests for the cloud emulation scripts

Offline tests of the live emulation scripts under `atomics/<ATT&CK-ID>/src/`. They
run with no cloud account and no network. Each test runs one script with a stub for
each cloud CLI (`gcloud`, `az`, `aws`, `curl`, and the other names in
`livetest.STUBS`). A stub makes no cloud call: it writes its arguments to a log,
prints the text the test gave it, and exits with the code the test gave it.

The script does not get the `PATH` of the caller. Its `PATH` has two directories
of the harness: the stubs, and links to the local programs in `livetest.TOOLS`
(`bash`, `cat`, `date`, `grep`, `sed` and some more). A script that calls a
different program stops with "command not found". Thus no test can run a real
network program by accident.

## Run them

```bash
python3 -B -m unittest discover -s atomics/tests -v
```

The CI job `emulation-scripts` in
[`.github/workflows/lint-trr.yml`](../../.github/workflows/lint-trr.yml) runs the
same command on each pull request. The command in the `Commands` block of
[`AGENTS.md`](../../AGENTS.md) is the short form.

## What they prove

- **Dry mode keeps its contract.** Each valid procedure letter exits 0 and makes no
  call; an invalid letter prints the usage line and exits 1; `--show-fixture`
  prints the committed fixture and makes no call.
- **Live mode runs the right commands.** With the stubs on `PATH`, a test asserts
  the exact sequence of calls for the happy path, and that a required account
  variable that is not set, or a name that does not start with the prefix of the
  technique, stops the run before any change (exit 2).
- **A run that knows it caused no record does not report success.** A CLI that
  is not installed, a procedure with no live run (TRR9018 b, d, e, TRR9020 b, d
  and TRR9023 b, c, d), a consent that no person accepted, an app role that
  Microsoft Graph does not have, a device-code flow that did not record a
  successful sign-in, and an answer of a CLI or of an endpoint that the script
  cannot use each revert what they made and exit 1. A test holds each of these
  ends: in a scratch copy, a change of each `exit 1` and each `exit 2` (outside
  the undo block) to `exit 0`, one at a time, made a test fail. That was done
  for the six scripts and for the copy of the TRR9020 script for upstream filing. Two runs end with exit 0 and write a record that does not fire the
  paired rule, by design: TRR9020 with a role that the rule does not match (the
  default `roles/viewer`), and TRR9038 b.
- **A secret is on no command line and in no output.** The access token of
  TRR9038 c, the OIDC token of TRR9023 and the device code of TRR9017 d go to
  `curl` on its standard input. A test looks for each value in each argument of
  each call and in the output of the run, at each end of the run. That includes
  the ends at which `curl` fails after the answer came: the answer of the
  endpoint holds a token or the device code, and the script does not print it.
  A run of TRR9038 c leaves no file in `TMPDIR`, in `HOME` and in the working
  directory.
- **A failed run reverts the changes that were made before the failure.** A test
  injects a failure at each command that makes a change and asserts that the
  changes before it are reverted (last-registered first), that the undo of the
  command that failed never runs, and that the exit code is not 0. The script
  cannot know if the provider made the change of the command that failed. It
  names that change, and the change can stay. TRR9038 c is different: its undo
  request accepts the answer "not found", so the script also sends it after a
  create request that got no answer or an error of the server (a status that is
  not 2xx and not 4xx).
- **No delete request with an answer that is not an ID.** When a create command
  ends with exit 0 and its answer is not one ID (the application of TRR9013 a;
  the application, the service principal, the grant and the app role assignment
  of TRR9017; the service account of TRR9018), the script stops with exit 1,
  names the change as one that can stay, and sends no delete request with that
  answer. For TRR9013 a and TRR9017, an ID holds letters, digits, `-` and `_`
  only, because it goes into the URL of a delete request: an answer that is
  empty, or that holds a blank, a tab, a line break, a carriage return, `/`, `?`
  or `.`, is not an ID.
- **The grant that a person makes is not left without a word.** In TRR9017 a,
  the person accepts the consent in a browser and presses Enter. From there to
  the registration of its undo, the grant is a change in progress: a read of
  the grants that fails, or a stop signal that stops that read, names the grant
  as a change that can stay; a stop signal that comes while the read runs to
  its end waits, and the run then removes the grant. A stop at the prompt
  (Ctrl-C before Enter) cannot know if the person accepted: the script says so
  before the prompt.
- **No undo line hides the failure of its command.** A test reads each `undo`
  line of the five scripts: it has no `||`, no `;` and no `eval`. That text check
  does not see a helper function that returns 0, a pipe, or a variable. So a
  second test (`livetest.each_undo_failure`) takes a good run of each procedure
  and makes each of its undo commands fail, one at a time: the run must end with
  exit 1, with one `LEFT BEHIND` line and no `[live] done.` line, and the other
  undo commands must run all the same.
- **The harness sees the files that a run leaves.** `test_livetest.py` is the
  positive control for `tmp_files` and `home_files`: a script that leaves a dot
  file, a file in a subdirectory, a file in the working directory and a file in
  `TMPDIR` gets each one listed.
- **A stop signal reverts the changes that were made.** `livetest.run_script` can
  send HUP, INT or TERM while a command runs: to the script only (the command then
  runs to its end, so its change is made and its undo must run), or to the script
  and the command as Ctrl-C does (the command stops in the middle; the script cannot
  know whether the provider made the change, so it reverts the earlier changes and
  names the one that can stay). A reader of the output that goes away does not stop
  the undo.

## What they cannot prove

A stub accepts every command, so these tests do **not** prove that a provider
accepts a command line or writes the record a rule reads. That is checked against
the provider reference when a script is written or corrected: the Google Cloud SDK
help for a `gcloud` command, and the Microsoft Learn `az` and Microsoft Graph pages
for an Entra command. Each provider page under [`docs/setup/`](../../docs/setup/)
lists what only a live run against a real account can show, in its "Not verified"
section.

## Add a test for a script

Use the harness [`livetest.py`](livetest.py). `livetest.run_script(path, *args,
env=..., outputs=..., fail=..., signals=..., files=..., tty=..., stubs=...)` runs
the script and returns a `Run` with `returncode`, `stdout`, `stderr`, `calls`
(one argument list per stub call), `stdins` (the text that came to each stub on
a pipe), `tmp_files` (the files that stay in `TMPDIR` after the run) and
`home_files` (the files that stay in `HOME`, which is also the working
directory). The docstring of `run_script` describes each parameter.
[`test_emulate_gcp_workforce.py`](test_emulate_gcp_workforce.py) is a worked
example. For each script, write at least:

- dry mode for each procedure letter (exit 0, no call);
- an invalid letter (exit 1);
- `--show-fixture` (prints the fixture, no call);
- live mode with a required variable not set (exit 2, no change);
- live mode without the CLI (`stubs=` with the name left out: exit 1, no call);
- each end at which the script knows that it caused no record (exit 1, no
  `[live] done.` line, the changes before it reverted);
- the live happy path (assert the exact call sequence);
- a failure injected at each change (assert the exact call list: the earlier
  changes reverted last-first, no undo for the command that failed, exit not 0);
- a failure of each undo command (`livetest.each_undo_failure` with the rules of
  the happy path of each procedure);
- a stop signal at each change (`signals=[(regex, name, scope)]`): scope `"shell"`
  reverts that change too, scope `"group"` names it as the change that can stay;
- what is special for the script (for example, that a token never reaches a
  command line and never reaches a file).

Prove that a new test can fail: in a scratch copy of the script, remove the
property the test checks and see the test turn red. Then restore the script.

## The undo block

Five scripts that make a change in live mode hold the shared undo block, byte for
byte, from [`undo_block.sh`](undo_block.sh) (indentation may differ). The
`MUST_HAVE` list in [`test_undo_block.py`](test_undo_block.py) names them. The
other live scripts that make a change do not hold the block:
[Problems in the live scripts](../../docs/setup/cloud-sandbox.md#problems-in-the-live-scripts)
lists them. When you give the block to a script, add the script to `MUST_HAVE`.
R9 moves the block to a shared file. The
block sits inside the live branch, after the check that the CLI is installed.
`test_undo_block.py` shows what the block does and checks that each listed script
holds the reference text with no change.

The block handles three things besides the planned end:

- **A signal** (HUP, INT, TERM) ends the run with exit 129, 130 or 143 and reverts
  the changes that were made. During the undo it keeps going (a second signal does
  not leave a half-reverted state). An undo command that was successful does not
  run again. An undo command that fails while a signal comes starts again,
  because the signal possibly stopped it. It starts again two times at most:
  when its third run fails in the same way, the block prints the `LEFT BEHIND`
  line for it and goes on with the other undo commands. So a person can stop an
  undo command that hangs (Ctrl-C three times) and still gets the command to run
  by hand. The count starts again for each undo command. A signal that comes when the run already ends (a command failed, the
  script stopped itself) does not skip the undo. A reader of the output that is
  gone (`| head`, a `tee` that a Ctrl-C stopped) does not stop the undo (the block
  ignores `SIGPIPE`).
- **A change in progress.** Before each command that makes a change, the script says
  `change_next <what>`; immediately after the command it registers the revert with
  `undo <command> <arguments>`. A signal that comes while the command runs waits for
  that `undo` line (the command finished, so its change is made and now has an undo);
  a signal that stops the command in the middle cannot know whether the change was
  made, so the block reverts the earlier changes and names this one as a change that
  can stay (`[live] The run stopped before the undo of this change was registered:`).
  The block prints the same two lines when the script stops itself between the
  command and its `undo` line (the answer was not an ID, or the provider refused the
  request).
- **The exit code.** At its planned end the script calls `undo_now`; `undo_now`
  itself stops the run (it does not print the last message) when an undo failed or a
  signal came, so a script does not read the block's internal state. When `undo_now`
  returns, each change is reverted, and from there the block ignores HUP, INT and
  TERM: a late signal does not make a good run fail. Thus a script only prints and
  ends after `undo_now` (a test reads the lines after each `undo_now` call). No
  cleanup command carries `|| true`.

One limit is known and is not closed. With bash 5.2.21, a stop signal that comes
at the moment when bash starts a command substitution (`$( )`) makes bash print
`unexpected EOF while looking for matching ')'`, and the trap of the signal does
not run. In a script with `set -e` the run then ends with exit 2, not with the code
of the signal. The exit path runs all the same: it reverts the registered changes
and names a change in progress. In a test loop with a signal each 0.3 ms, each form
of command substitution gave that error some times (in an array assignment, in a
function, at the top level), and `printf -v` gave it in none of 14 runs. So the block
holds no command substitution (a test checks that), and a registration is not lost
in this way. A script line such as `ID="$(az ... create ...)"` still can be hit: the
run then names that change as one that can stay. The fault has a second form: in
a command substitution inside an undo command (the delete request of TRR9038 c),
bash prints the same line and the signal is lost, so the undo command runs to its
end and the run goes on as if no signal came. Other versions of bash were not
tried.
