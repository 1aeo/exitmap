#!/usr/bin/env python3
"""Apply one mutant at a time to src/eventhandler.py of a copy of the mr18
tree and run test/test_eventhandler.py.  Run trace_pause.py on every mutant
which the tests do not catch.

usage: mutate18.py <tree> <python>

<tree> must be an export of mr18/ignore-late-events: the mutants are made
for its code and the script stops if one of them does not apply.  <python>
needs pytest, stem and PySocks.

Mutants marked "race" change only what happens when two threads run at the
same time.  The unit tests and the race scripts late_events.py,
during_giveup.py and three_modules.py count the same with them, because
wait() sets already_finished before anything they deliver is handled.
trace_pause.py holds the queue reader or new_circuit() on the line that
counts while wait() gives up; it counts an event twice with each of them."""
import os
import shutil
import subprocess
import sys
import tempfile

TREE, PY = os.path.abspath(sys.argv[1]), sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(TREE, 'src/eventhandler.py')).read()

I20 = ' ' * 20
READER_GUARD = '''                with self.check_finished_lock:
                    # Once the scan is over, e.g. because wait() gave up on
                    # this process, it is not counted.
                    if not self.already_finished:
                        self.stats.finished_streams += 1
'''
READER_CLOSING = '                log.debug("Closing finished circuit %s.", circ_id)\n'
CIRC_GUARD = '''        with self.check_finished_lock:
            # Once the scan is over, e.g. because wait() gave up on this
            # circuit, neither count it nor start a module process for it.
            if self.already_finished:
                return
            self.stats.update_circs(circ_event)
'''
GIVEUP_LOCK = '                with self.check_finished_lock:\n'
GIVEUP_END = '                    self.stats.finished_streams += modules\n'


def r(old, new):
    """A mutant which replaces old, which must occur exactly once."""
    def mutate(s):
        if s.count(old) != 1:
            sys.exit("mutate18.py: %d matches for %r" % (s.count(old), old))
        return s.replace(old, new, 1)
    return mutate


def dedent_giveup(s):
    """The give-up without the lock (race)."""
    a = s.index(GIVEUP_LOCK, s.index('if time.monotonic() - self.last_message'))
    b = s.index(GIVEUP_END, a) + len(GIVEUP_END)
    body = s[a + len(GIVEUP_LOCK):b]
    body = ''.join(l[4:] if l.startswith(I20) else l
                   for l in body.splitlines(True))
    return s[:a] + body + s[b:]


def only_late(status):
    return r(CIRC_GUARD, CIRC_GUARD.replace(
        'if self.already_finished:',
        'if (self.already_finished and\n'
        '                    circ_event.status == CircStatus.%s):' % status))


def reader_on_late_report(code):
    """The reader does something else with a late report, right after it
    closed the circuit and before it counts."""
    return r(READER_GUARD, '                if self.already_finished:\n'
             '                    %s\n' % code + READER_GUARD)


MUT = {
    # mr18 itself
    'give-up does not set already_finished': r(
        I20 + 'self.already_finished = True\n', ''),
    'give-up does not set finished_event': r(
        I20 + 'self.finished_event.set()\n', ''),
    'reader counts every report': r(
        READER_GUARD, READER_GUARD.replace(
            '                    if not self.already_finished:\n'
            '                        self.stats.finished_streams += 1\n',
            '                    self.stats.finished_streams += 1\n')),
    'reader guard inverted': r('if not self.already_finished:',
                               'if self.already_finished:'),
    'reader skips a late report': r(
        READER_CLOSING, READER_CLOSING +
        '                if self.already_finished:\n'
        '                    continue\n'),
    'reader hangs on a late report': reader_on_late_report(
        'threading.Event().wait()'),
    'reader dies on a late report': reader_on_late_report(
        'raise RuntimeError("late report")'),
    'new_circuit counts every event': r(CIRC_GUARD, CIRC_GUARD.replace(
        '            if self.already_finished:\n                return\n', '')),
    'new_circuit counts, then returns': r(CIRC_GUARD, CIRC_GUARD.replace(
        '            if self.already_finished:\n                return\n'
        '            self.stats.update_circs(circ_event)\n',
        '            self.stats.update_circs(circ_event)\n'
        '            if self.already_finished:\n                return\n')),
    'new_circuit skips counting, still starts module': r(
        CIRC_GUARD, CIRC_GUARD.replace(
            '            if self.already_finished:\n                return\n'
            '            self.stats.update_circs(circ_event)\n',
            '            if not self.already_finished:\n'
            '                self.stats.update_circs(circ_event)\n')),
    'new_circuit ignores only late BUILT': only_late('BUILT'),
    'new_circuit ignores only late FAILED': only_late('FAILED'),
    'race: reader without lock': r(READER_GUARD, ''.join(
        l[4:] for l in READER_GUARD.splitlines(True)[1:])),
    'race: new_circuit without lock': r(CIRC_GUARD, ''.join(
        l[4:] for l in CIRC_GUARD.splitlines(True)[1:])),
    'race: give-up without lock': dedent_giveup,
    'flag set after the corrections (same lock)': lambda s: r(
        GIVEUP_END, GIVEUP_END + I20 + 'self.already_finished = True\n')(
        r(I20 + 'self.already_finished = True\n', '')(s)),
    # mr16, inside the lock now
    'no failed correction': r(I20 + 'self.stats.failed_circuits += circuits\n',
                              ''),
    'no finished correction': r(GIVEUP_END, ''),
    'corrections swapped': lambda s: r(
        'self.stats.finished_streams += modules',
        'self.stats.failed_circuits += modules')(r(
            'self.stats.failed_circuits += circuits',
            'self.stats.finished_streams += circuits')(s)),
    'one finished stream too many': r(
        'self.stats.finished_streams += modules',
        'self.stats.finished_streams += modules + 1'),
    'failed = circuits': r('self.stats.failed_circuits += circuits',
                           'self.stats.failed_circuits = circuits'),
    'finished = modules': r('self.stats.finished_streams += modules',
                            'self.stats.finished_streams = modules'),
    'modules minus failed (upstream rule)': r(
        '''                    modules = max(0, self.stats.successful_circuits -
                                  self.stats.finished_streams)''',
        '''                    modules = max(0, self.stats.successful_circuits -
                                  self.stats.failed_circuits -
                                  self.stats.finished_streams)'''),
    'no break after giving up': r(
        '''                            IDLE_TIMEOUT, circuits, modules)
                break
''', '''                            IDLE_TIMEOUT, circuits, modules)
'''),
    '> instead of >=': r('self.last_message >= IDLE_TIMEOUT',
                         'self.last_message > IDLE_TIMEOUT'),
    'warning at debug level': r(
        'log.warning("No message from a module process',
        'log.debug("No message from a module process'),
}


def trace_pause(src, name):
    p = subprocess.run([PY, '-I', os.path.join(HERE, 'trace_pause.py'), src,
                        name], capture_output=True, text=True, timeout=120)
    verdicts = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) > 2:
            verdicts.append('%s %s' % (parts[1], 'ok' if line.endswith(': ok')
                                       else 'COUNTED TWICE'))
    return ', '.join(verdicts) or 'no output: ' + p.stderr[-200:]


print('tree:', TREE)
for name, fn in MUT.items():
    mutated = fn(SRC)
    if mutated == SRC:
        sys.exit('mutate18.py: %s changes nothing' % name)
    compile(mutated, 'eventhandler.py', 'exec')
    d = tempfile.mkdtemp()
    try:
        shutil.copytree(TREE, d, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('.git', '__pycache__'))
        open(os.path.join(d, 'src/eventhandler.py'), 'w').write(mutated)
        p = subprocess.run([PY, '-B', '-m', 'pytest', '-q', '-x',
                            '-p', 'no:cacheprovider', '--no-cov',
                            '-o', 'log_cli=false',
                            'test/test_eventhandler.py'],
                           cwd=d, capture_output=True, text=True,
                           timeout=300,
                           env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        last = [l for l in p.stdout.splitlines() if l.strip()][-1:]
        last = last[0] if last else ''
        if p.returncode != 0:
            print('%-48s killed   %s' % (name, last), flush=True)
        else:
            print('%-48s SURVIVED %s | trace_pause: %s' % (
                name, last, trace_pause(os.path.join(d, 'src'), 'mutant')),
                flush=True)
    finally:
        shutil.rmtree(d)
