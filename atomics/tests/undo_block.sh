# >>> live undo (the same text in each live script; atomics/tests/undo_block.sh is the reference)
_UNDO=()      # the commands that revert the changes
_LEFT=0       # 1 after an undo command failed
_SIG=0        # the exit code of the first stop signal: 129 HUP, 130 INT, 143 TERM
_HIT=0        # 1 after a stop signal came while an undo command ran
_BUSY=""      # the change that the next command makes: set by change_next, cleared by undo
_UNDOING=0    # 1 while the undo commands run
change_next() { _BUSY="$*"; }                   # say this before each command that makes a change
undo() {                                        # after the command: register the command that reverts the change
  local quoted
  printf -v quoted '%q ' "$@"                   # no command substitution: a stop signal in one can end bash with a syntax error
  _UNDO+=("$quoted")
  _BUSY=""
  if [[ $_SIG -ne 0 ]]; then exit "$_SIG"; fi   # a stop signal waited for this registration
}
_undo_run() {                                   # run the registered commands, last registered first
  local i runs
  _UNDOING=1
  while (( ${#_UNDO[@]} > 0 )); do
    i=$(( ${#_UNDO[@]} - 1 ))
    echo "[live] undo: ${_UNDO[$i]}"
    runs=0
    while :; do
      _HIT=0
      runs=$(( runs + 1 ))
      if eval "${_UNDO[$i]}" >/dev/null; then break; fi
      if [[ $_HIT -eq 0 || $runs -ge 3 ]]; then   # it failed with no stop signal, or a stop signal came in each of 3 runs
        echo "[live] LEFT BEHIND, this command failed: ${_UNDO[$i]}" >&2; _LEFT=1; break
      fi
      echo "[live] a stop signal came and this undo command failed: it starts again" >&2
    done
    unset "_UNDO[$i]"                           # a command that ran to its end does not run again
  done
}
undo_now() {                                    # the planned end: revert each change, then go on only if all is good
  _undo_run
  _UNDOING=0                                    # from here to the last line, a stop signal stops the run at once
  if [[ $_SIG -ne 0 ]]; then exit "$_SIG"; fi   # a stop signal came: do not print "done"
  if [[ $_LEFT -ne 0 ]]; then exit 1; fi        # an undo failed: do not print "done"
  trap '' HUP INT TERM                          # each change is reverted: a late stop signal must not fail a good run
}
_on_exit() {
  local code=$?
  trap - EXIT
  set +e
  if [[ $_SIG -ne 0 ]]; then code=$_SIG; fi
  if [[ -n "$_BUSY" ]]; then
    echo "[live] The run stopped before the undo of this change was registered: $_BUSY" >&2
    echo "[live] That change has no undo. If the provider made it, it stays: do the check and remove it." >&2
  fi
  _undo_run
  if [[ $code -eq 0 && $_LEFT -ne 0 ]]; then code=1; fi
  if [[ $code -ne 0 ]]; then
    echo "[live] FAILED (exit $code). Read the lines above. Then do the check that nothing stays behind (docs/setup/)." >&2
  fi
  exit "$code"
}
_stop() {                                       # a stop signal came
  if [[ $_SIG -eq 0 ]]; then _SIG=$1; fi
  if [[ $_UNDOING -ne 0 ]]; then
    _HIT=1
    echo "[live] signal during the undo: the undo continues" >&2
  elif [[ -n "$_BUSY" ]]; then
    echo "[live] stop signal during a change: the run stops after this change" >&2
  else
    _on_exit                                    # not a plain exit: bash does not start the EXIT trap a second time
  fi
}
trap _on_exit EXIT
trap '_stop 129' HUP
trap '_stop 130' INT
trap '_stop 143' TERM
trap '' PIPE                                    # a reader of the output that is gone must not stop the undo
# <<< live undo
