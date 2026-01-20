# Copyright 2013-2020 Philipp Winter <phw@nymity.ch>
# Copyright 2021 The Tor Project, Inc.
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Handles Tor controller events.
"""

import os
import sys
import functools
import threading
import multiprocessing
import logging
import socket

import stem
from stem import StreamStatus
from stem import CircStatus

import torsocks

import error
import command
import util

log = logging.getLogger(__name__)


def get_relay_desc(controller, fpr):
    """
    Return the descriptor for the given relay fingerprint."
    """

    desc = None
    try:
        desc = controller.get_server_descriptor(relay=fpr)
    except stem.DescriptorUnavailable as err:
        log.warning("Descriptor for %s not available: %s" % (fpr, err))
    except stem.ControllerError as err:
        log.warning("Unable to query for %d: %s" % (fpr, err))
    except ValueError:
        log.warning("%s is malformed.  Is it a relay fingerprint?" % fpr)

    return desc


class Attacher(object):

    """
    Attaches streams to circuits.
    """

    def __init__(self, controller):

        # Maps port to function that attached a stream to a circuit.

        self.unattached = {}
        self.controller = controller
        self._lock = threading.Lock()  # Protect against concurrent access

    def prepare(self, port, circuit_id=None, stream_id=None):
        """
        Prepare for attaching a stream to a circuit.

        If we already have the corresponding stream/circuit, we can attach it
        now.  Otherwise, the method _attach() is partially executed and stored,
        so it can be attached later.

        Thread-safe: Uses a lock to protect the shared unattached dictionary
        from concurrent access by the queue_reader thread and main event thread.
        """

        assert ((circuit_id is not None) and (stream_id is None)) or \
               ((circuit_id is None) and (stream_id is not None))

        # Thread-safe access to the shared dictionary
        with self._lock:
            # Use pop() to atomically get and remove, avoiding check-then-delete race
            attach = self.unattached.pop(port, None)

            if attach is not None:
                # We had a pending attacher - complete it
                if circuit_id:
                    attach(circuit_id=circuit_id)
                else:
                    attach(stream_id=stream_id)
            else:
                # We maintain a dictionary of source ports that point to their
                # respective attaching function.  At this point we only know either
                # the stream or the circuit ID, so we store a partially executed
                # function.

                if circuit_id:
                    partially_attached = functools.partial(self._attach,
                                                           circuit_id=circuit_id)
                    self.unattached[port] = partially_attached
                else:
                    partially_attached = functools.partial(self._attach,
                                                           stream_id=stream_id)
                    self.unattached[port] = partially_attached

            log.debug("Pending attachers: %d." % len(self.unattached))

    def _attach(self, stream_id=None, circuit_id=None):
        """
        Attach a stream to a circuit.
        """

        log.debug("Attempting to attach stream %s to circuit %s." %
                  (stream_id, circuit_id))

        try:
            self.controller.attach_stream(stream_id, circuit_id)
        except stem.OperationFailed as err:
            log.warning("Failed to attach stream because: %s" % err)


def module_call(queue, module, circ_id, socks_port,
            exit_desc,
            run_cmd_over_tor,
            destinations,
            target_host,
            target_port,
            first_hop_fpr=None
            ):
    """
    Run the module and then inform the event handler.

    The invoking process keeps track of which circuits finished.  Once we
    are done, we send a signal over the queue to let the process know.
    """
    def run_python_over_tor_wrapper(queue, circ_id, socks_port):
        """
        Returns a closure to route a Python function's network traffic over Tor.
        """

        def closure(func, *args):
            """
            Route the given Python function's network traffic over Tor.
            We temporarily monkey-patch socket.socket using our torsocks
            module, and reset it once the function returns.
            """
            try:
                with torsocks.MonkeyPatchedSocket(queue, circ_id, socks_port):
                    func(*args)
            except (error.SOCKSv5Error, socket.error) as err:
                log.info(err)
                return

        return closure

    try:
        module(
            exit_desc=exit_desc,
            run_python_over_tor=run_python_over_tor_wrapper(queue, circ_id, socks_port),
            run_cmd_over_tor=run_cmd_over_tor,
            destinations=destinations,
            target_host=target_host,
            target_port=target_port,
            first_hop=first_hop_fpr
        )
        log.debug("Informing event handler that module finished.")
        queue.put((circ_id, None))
    except KeyboardInterrupt:
        pass


class EventHandler(object):

    """
    Handles asynchronous Tor events.

    The handler processes only stream and circuit events.  New streams are
    attached to their corresponding circuits since exitmap's Tor process leaves
    new streams unattached.
    """

    def __init__(self, controller, module, socks_port, stats, exit_destinations, target_host, target_port):

        self.stats = stats
        self.controller = controller
        self.attacher = Attacher(controller)
        self.module = module
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()
        self.socks_port = socks_port
        self.exit_destinations = exit_destinations
        self.target_host = target_host
        self.target_port = target_port
        self.check_finished_lock = threading.Lock()
        self.already_finished = False
        self.pid_to_fingerprint = {}  # {pid: fingerprint} for grace period

        queue_thread = threading.Thread(target=self.queue_reader)
        queue_thread.daemon = False
        queue_thread.start()

    def queue_reader(self):
        """
        Read (circuit ID, sockname) tuples from invoked probing modules.

        These tuples are then used to attach streams to their corresponding
        circuits.
        """

        log.debug("Starting thread to read from IPC queue.")

        while True:
            try:
                circ_id, sockname = self.queue.get()
            except EOFError:
                log.debug("IPC queue terminated.")
                break

            # Over the queue, a module can either signal that it finished
            # execution (by sending (circ_id,None)) or that it is ready to have
            # its stream attached to a circuit (by sending (circ_id,sockname)).

            if sockname is None:
                log.debug("Closing finished circuit %s." % circ_id)
                try:
                    self.controller.close_circuit(circ_id)
                except stem.InvalidArguments as err:
                    log.debug("Could not close circuit because: %s" % err)

                self.stats.finished_streams += 1
                self.stats.print_progress()
                self.check_finished()
            else:
                log.debug("Read from queue: %s, %s" % (circ_id, str(sockname)))
                port = int(sockname[1])
                self.attacher.prepare(port, circuit_id=circ_id)
                self.check_finished()

    def check_finished(self):
        """
        Check if the scan is finished and if it is, shut down exitmap.
        """

        # This is called from both the queue reader thread and the
        # main thread, but (if it detects completion) does things that
        # must only happen once.
        with self.check_finished_lock:
            if self.already_finished:
                sys.exit(0)

            # Did all circuits either build or fail?
            circs_done = ((self.stats.failed_circuits +
                           self.stats.successful_circuits) ==
                          self.stats.total_circuits)

            # Was every built circuit attached to a stream?
            streams_done = (self.stats.finished_streams >=
                            (self.stats.successful_circuits -
                             self.stats.failed_circuits))

            log.debug("failedCircs=%d, builtCircs=%d, totalCircs=%d, "
                      "finishedStreams=%d" % (self.stats.failed_circuits,
                                              self.stats.successful_circuits,
                                              self.stats.total_circuits,
                                              self.stats.finished_streams))

            if circs_done and streams_done:
                self.already_finished = True

                # Grace period for straggling processes (split timeout across all)
                terminated, active = [], multiprocessing.active_children()
                if active:
                    per_proc = max(1, int(os.environ.get("EXITMAP_GRACE_TIMEOUT", "10")) // len(active))
                    for proc in active:
                        proc.join(timeout=per_proc)
                        if proc.is_alive():
                            if fpr := self.pid_to_fingerprint.get(proc.pid):
                                terminated.append(fpr)
                            proc.terminate()
                if terminated:
                    log.info("Terminated %d stalled relays" % len(terminated))

                if hasattr(self.module, "teardown"):
                    try:
                        self.module.teardown(
                            stats=self.stats, controller=self.controller,
                            terminated_relays=terminated
                        )
                    except TypeError:
                        # Module doesn't accept kwargs - call without arguments
                        self.module.teardown()

                log.info(self.stats)
                sys.exit(0)

    def new_circuit(self, circ_event):
        """
        Invoke a new probing module when a new circuit becomes ready.
        """
        # stats.update_circs() uses the circuit registry to look up the intended path
        # (registered in exitmap.py when we call controller.new_circuit())
        self.stats.update_circs(circ_event)
        self.check_finished()

        if circ_event.status not in [CircStatus.BUILT]:
            return

        # Extract fingerprints from the built circuit path
        first_hop = circ_event.path[0]
        first_hop_fpr = first_hop[0]
        last_hop = circ_event.path[-1]
        exit_fpr = last_hop[0]
        
        log.debug("Circuit for exit relay \"%s\" is built (first hop: %s).  "
                  "Now invoking probing module." % (exit_fpr, first_hop_fpr))

        run_cmd_over_tor = command.Command(self.queue,
                                           circ_event.id,
                                           self.socks_port)

        exit_desc = get_relay_desc(self.controller, exit_fpr)
        if exit_desc is None:
            self.controller.close_circuit(circ_event.id)
            return

        proc = multiprocessing.Process(target=module_call, args=(
            self.queue,
            self.module.probe,
            circ_event.id,
            self.socks_port,
            exit_desc,
            run_cmd_over_tor,
            self.exit_destinations[exit_fpr],
            self.target_host,
            self.target_port,
            first_hop_fpr
        ))
        proc.daemon = True
        proc.start()
        self.pid_to_fingerprint[proc.pid] = exit_fpr

    def new_stream(self, stream_event):
        """
        Create a function which is later used to attach a stream to a circuit.

        The attaching cannot be done right now as we do not know the stream's
        desired circuit ID at this point.  So we set up all we can at this
        point and wait for the attaching to be done in queue_reader().
        """

        if stream_event.status not in [StreamStatus.NEW,
                                       StreamStatus.NEWRESOLVE]:
            return

        port = util.get_source_port(str(stream_event))
        if not port:
            log.warning("Couldn't extract source port from stream "
                        "event: %s" % str(stream_event))
            return

        log.debug("Adding attacher for new stream %s." % stream_event.id)
        self.attacher.prepare(port, stream_id=stream_event.id)
        self.check_finished()

    def new_event(self, event):
        """
        Dispatches new Tor controller events to the appropriate handlers.
        """

        if isinstance(event, stem.response.events.CircuitEvent):
            self.new_circuit(event)

        elif isinstance(event, stem.response.events.StreamEvent):
            self.new_stream(event)

        else:
            log.warning("Received unexpected event %s." % str(event))
