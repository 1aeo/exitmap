"""Runs all scenarios against one or more stem trees.

usage: run_all.py <notor|withtor|withsock> <runs> <stem tree> [<stem tree> ...]

A scenario is one of the variants in variants.py.  The first argument is the
family, the script that runs them: notor.py, withtor.py or withsock.py.
Every run is a process of its own, started with the python that runs this
script.  Prints a table with a row for every scenario and a column for every
stem tree: blocked runs/runs, plus any verdict other than OK and BLOCKED.
Totals for three groups of scenarios follow.

withtor and withsock start a tor for every run.  It listens on control port
28750, or on the one in the environment variable SCENARIO_PORT.  Its files
are in a temporary directory that is removed at the end.  The environment
variable SCENARIO_SCRATCH names the directory to make that one in (default:
where python makes temporary files).  For withsock its path must be short,
see withsock.py.

Exit status: 0 if every run ended as OK or BLOCKED, 1 if not, 2 if the
arguments are wrong.
"""
import collections
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 120  # seconds for one run, it ends itself after common.HARD_LIMIT

# What every family runs, in this order.  These are the lists of the measured
# runs (see README.md): all scenarios without tor, 29 of them with a real tor
# on a ControlPort, 20 of those with a real tor on a ControlSocket.

NOTOR = ('1', '2', '3a', '3b', '4', '5', '5b', '6a', '6a2', '6b', '6c', '6d', '6d2', '6e', '4L', '7', '7r', 'q', 'qw', '4b', '4E', '3c', '3e', '3f', 's1', 'w', 'x1', 'x2', 'x3', 'j1', 'j2', 'p3', 'k1', 'e1', 'c1')
WITHSOCK = NOTOR[:20]
WITHTOR = WITHSOCK + ('3c', 's1', 'w', 'x1', 'x2', 'j1', 'p3', 'k1', 'c1')
FAMILIES = {'notor': NOTOR, 'withtor': WITHTOR, 'withsock': WITHSOCK}

# The groups the totals are for, and what to expect of them:
#
#   tor goes away and the reader thread joins the event thread (the bug)
#     Blocks on unmodified stem, never with the fix.  7r and q are races, on
#     unmodified stem they do not block in every run.
#
#   not covered by the fix
#     Blocks with and without the fix.
#
#   work today and must keep working
#     Never blocks.

GROUPS = (
  ('tor goes away and the reader thread joins the event thread (the bug)', ('1', '2', '5', '5b', '4L', '7', '7r', 'q', 'qw', '4E', 'j1', 'j2', 'k1')),
  ('not covered by the fix', ('3a', '3b', '3c', '3e', '3f', 's1', 'w', 'x1', 'p3')),
  ('work today and must keep working', ('4', '6a', '6a2', '6b', '6c', '6d', '6d2', '6e', '4b', 'x2', 'x3', 'e1', 'c1')),
)


def stop(pid):
  """Kills what is left of a run: the processes of its process group."""

  try:
    os.killpg(pid, signal.SIGKILL)
  except OSError:
    pass  # nothing is left


def run_once(family, scenario, tree, port, scratch):
  """
  Runs one scenario in a process of its own.  Returns its verdict and the
  lines it printed.
  """

  cmd = [sys.executable, '-B', os.path.join(HERE, family + '.py'), tree, scenario]

  if family != 'notor':
    cmd += [str(port), scratch]

  # setsid: the run and the tor it starts get a process group of their own.
  # REPRO_DUMP: blocked runs need not dump their threads, see common.py.

  env = dict(os.environ, REPRO_DUMP = '0')
  began = time.time()
  proc = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT, env = env, preexec_fn = os.setsid)
  timer = threading.Timer(TIMEOUT, stop, (proc.pid,))
  timer.start()

  try:
    output = proc.stdout.read()  # returns when the run ended, or when the timer ended it
  finally:
    timer.cancel()
    timer.join()

    # We did not wait() for the run yet, so its process group can't be
    # another's by now.  This is for a tor the run did not get to stop.

    stop(proc.pid)
    proc.stdout.close()
    proc.wait()

  lines = output.decode('utf-8', 'replace').splitlines()
  verdicts = [line.split()[1] for line in lines if line.startswith('RESULT ')]

  if time.time() - began >= TIMEOUT:
    lines.append('(ended after %i seconds)' % TIMEOUT)

  return (verdicts[0] if verdicts else 'ERROR'), lines


def cell(verdicts):
  """Blocked runs/runs, and what else there was."""

  text = '%i/%i' % (verdicts['BLOCKED'], sum(verdicts.values()))

  for verdict in sorted(verdicts):
    if verdict not in ('OK', 'BLOCKED'):
      text += ' +%i %s' % (verdicts[verdict], verdict)

  return text


def row(first, cells, last = ''):
  return ('%-9s %s %s' % (first, ' '.join('%-15s' % c for c in cells), last)).rstrip()


def main():
  if len(sys.argv) < 4 or sys.argv[1] not in FAMILIES or not sys.argv[2].isdigit():
    sys.stderr.write(__doc__.split('\n\n')[1] + '\n')
    sys.exit(2)

  family, runs = sys.argv[1], int(sys.argv[2])
  trees = [os.path.abspath(tree) for tree in sys.argv[3:]]
  columns = range(len(trees))
  scenarios = FAMILIES[family]
  port = int(os.environ.get('SCENARIO_PORT', '28750'))

  for tree in trees:
    if not os.path.isfile(os.path.join(tree, 'stem', 'control.py')):
      sys.stderr.write('%s is not a stem tree, it has no stem/control.py\n' % tree)
      sys.exit(2)

  print('%s: %i scenarios, runs of each per stem tree: %i, python %s' % (family, len(scenarios), runs, sys.version.split()[0]))

  for column in columns:
    print('tree %i: %s' % (column + 1, trees[column]))

  header = ['tree %i' % (column + 1) for column in columns]
  print('')
  print(row('scenario', header, '(blocked runs/runs)'))
  sys.stdout.flush()

  scratch = None
  counts = {}  # (scenario, column) => verdicts of its runs
  problems = []  # runs that were neither OK nor BLOCKED
  began = time.time()

  if family != 'notor':
    scratch = tempfile.mkdtemp(prefix = 'scenarios-', dir = os.environ.get('SCENARIO_SCRATCH'))

  try:
    for scenario in scenarios:
      for column in columns:
        counts[(scenario, column)] = collections.Counter()

        for number in range(runs):
          verdict, lines = run_once(family, scenario, trees[column], port, scratch)
          counts[(scenario, column)][verdict] += 1

          if verdict not in ('OK', 'BLOCKED'):
            problems.append((scenario, column, number, verdict, lines))

      print(row(scenario, [cell(counts[(scenario, column)]) for column in columns]))
      sys.stdout.flush()
  finally:
    if scratch:
      shutil.rmtree(scratch, ignore_errors = True)

  print('')
  print(row('totals', header))

  for name, members in GROUPS:
    members = [scenario for scenario in scenarios if scenario in members]
    totals = [sum((counts[(scenario, column)] for scenario in members), collections.Counter()) for column in columns]
    print(row('', [cell(total) for total in totals], name))

  for scenario, column, number, verdict, lines in problems:
    print('')
    print('%s: scenario %s, tree %i, run %i' % (verdict, scenario, column + 1, number + 1))

    if verdict == 'ERROR':
      shown = lines[-15:] or ['(no output)']  # there is no RESULT line, so the end of what there is
    else:
      shown = [line for line in lines if line.startswith('  WRONG:')]

    for line in shown:
      print(('  ' + line).rstrip())

  print('')
  print('%i runs in %i seconds' % (len(scenarios) * len(trees) * runs, time.time() - began))
  sys.exit(1 if problems else 0)


if __name__ == '__main__':
  main()
