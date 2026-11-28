"""Shared pieces of the stem close() deadlock reproducers.

Everything a variant starts is recorded as an Activity.  When a variant is
over, anything that was started and has not finished is blocked: we print a
one-line position for every thread, the full faulthandler dump, and exit 1.
"""
import faulthandler
import os
import sys
import threading
import time
import traceback

HARD_LIMIT = 60  # seconds, in case the reproducer blocks itself


class Activity(object):
  """Something that runs in a thread: a listener call or a call we make."""

  def __init__(self, name):
    self.name = name
    self.started = threading.Event()
    self.finished = threading.Event()
    self.started_at = self.finished_at = None
    self.outcome = None

  def start(self):
    self.started_at = time.time()
    self.thread = threading.current_thread().name
    self.started.set()

  def finish(self, outcome):
    self.outcome = outcome
    self.finished_at = time.time()
    self.finished.set()

  def run(self, func):
    self.start()

    try:
      value = func()
      self.finish('returned' if value is None else 'returned %r' % (value,))
    except Exception as exc:
      self.finish('raised %s' % type(exc).__name__)

  def describe(self):
    if not self.started.is_set():
      return 'never started'
    elif not self.finished.is_set():
      return 'BLOCKED'
    else:
      return '%s after %0.3fs' % (self.outcome, self.finished_at - self.started_at)


class Run(object):
  """One run of one variant."""

  def __init__(self, patience):
    self.patience = patience  # seconds until we call something blocked
    self.activities = []  # in the order they were created
    self.notes = []
    self.failures = []  # things that returned, but not as they should
    self.began = time.time()
    faulthandler.dump_traceback_later(HARD_LIMIT, exit = True)

  def activity(self, name):
    activity = Activity(name)
    self.activities.append(activity)
    return activity

  def call(self, name, func):
    """Calls func in a new thread, returns right away."""

    activity = self.activity(name)
    thread = threading.Thread(target = activity.run, args = (func,), name = name)
    thread.daemon = True
    thread.start()
    return activity

  def listener(self, name, func, expected = 1):
    """
    Event listener that calls func(event, call number).  Returns it with the
    activities of its first calls, so they can be waited for.
    """

    activities = [self.activity(name if i == 0 else '%s (event %i)' % (name, i + 1)) for i in range(expected)]
    calls = []

    def listener(event):
      calls.append(event)
      number = len(calls)

      if number > len(activities):
        activities.append(self.activity('%s (event %i)' % (name, number)))

      activities[number - 1].run(lambda: func(event, number))

    return listener, activities

  def wait(self, *activities):
    """Waits until these finished, at most our patience for all of them."""

    deadline = time.time() + self.patience

    for activity in activities:
      activity.finished.wait(max(0, deadline - time.time()))

    return all(activity.finished.is_set() for activity in activities)

  def wait_started(self, activity):
    if not activity.started.wait(self.patience):
      self.fail('%s never started' % activity.name)

  def note(self, msg):
    self.notes.append(msg)

  def fail(self, msg):
    self.failures.append(msg)

  def check(self, condition, msg):
    if not condition:
      self.fail(msg)

  def expect(self, activity, outcome_prefix):
    """Notes a failure if a finished activity ended in an other way."""

    if activity.finished.is_set() and not activity.outcome.startswith(outcome_prefix):
      self.fail('%s %s, expected: %s' % (activity.name, activity.outcome, outcome_prefix))

  def report(self, label, cleanup = None):
    """Prints what happened and exits: 0 fine, 1 blocked, 2 wrong outcome."""

    blocked = [a for a in self.activities if a.started.is_set() and not a.finished.is_set()]
    print(label)

    for activity in self.activities:
      print('  %-28s %s' % (activity.name + ':', activity.describe()))

    for note in self.notes:
      print('  note: %s' % note)

    for failure in self.failures:
      print('  WRONG: %s' % failure)

    if blocked:
      print('  where the threads are (innermost frame first):')

      for line in where():
        print('    %s' % line)

    verdict = 'BLOCKED' if blocked else ('WRONG' if self.failures else 'OK')
    print('RESULT %s %s (%0.2fs)' % (verdict, ', '.join(a.name for a in blocked), time.time() - self.began))
    sys.stdout.flush()

    if blocked and os.environ.get('REPRO_DUMP', '1') == '1':
      faulthandler.dump_traceback(all_threads = True)

    if cleanup:
      cleanup()

    sys.stdout.flush()
    os._exit(1 if blocked else (2 if self.failures else 0))


def where():
  """One line for every thread: its innermost frames, without the noise."""

  frames = sys._current_frames()
  lines = []

  for thread in sorted(threading.enumerate(), key = lambda t: t.name):
    if thread is threading.current_thread() or thread.ident not in frames or thread.name.startswith('fake tor'):
      continue

    stack = []

    for frame in reversed(traceback.extract_stack(frames[thread.ident])):
      path, filename = os.path.split(frame.filename)

      if filename == 'threading.py' and frame.name in ('run', '_bootstrap', '_bootstrap_inner'):
        continue
      elif filename == 'common.py':
        continue

      if os.path.basename(path) == 'stem':
        filename = 'stem/' + filename

      stack.append('%s:%i %s' % (filename, frame.lineno, frame.name))

    lines.append('%-18s => %s' % (thread.name, ' < '.join(stack[:7])))

  return lines


def hook_closing(controller):
  """
  Event that is set when the controller's socket was marked as closed and
  BaseController._close() is about to run, in whatever thread closes it.
  """

  closing = threading.Event()
  control_socket = controller.get_socket()
  controller_close = control_socket._close

  def _close():
    closing.set()
    controller_close()

  control_socket._close = _close
  return closing


def settle(controller):
  """
  Call this once tor received (or must have been sent) a request: returns when
  the sender is out of ControlSocket.send(), which holds the send lock.
  """

  with controller.get_socket()._get_send_lock():
    pass
