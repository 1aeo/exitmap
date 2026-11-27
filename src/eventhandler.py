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

import functools
import socket
import threading
import multiprocessing
import logging
import queue
import time
import stem
from stem import StreamStatus
from stem import CircStatus

import error
import torsocks

import command
import util

log = logging.getLogger(__name__)

# wait() gives up once no module process has sent us a message for this many
# seconds.
IDLE_TIMEOUT = 300


def get_relay_desc(controller, fpr):
    """
    Return the descriptor for the given relay fingerprint."
    """

    desc = None
    try:
        desc = controller.get_server_descriptor(relay=fpr)
    except stem.DescriptorUnavailable as err:
        log.warning("Descriptor for %s not available: %s", fpr, err)
    except stem.ControllerError as err:
        log.warning("Unable to query for %s: %s", fpr, err)
    except ValueError:
        log.warning("%s is malformed.  Is it a relay fingerprint?", fpr)

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

            log.debug("Pending attachers: %d.", len(self.unattached))

    def _attach(self, stream_id=None, circuit_id=None):
        """
        Attach a stream to a circuit.
        """

        log.debug("Attempting to attach stream %s to circuit %s.",
                  stream_id, circuit_id)

        if not self.controller.is_alive():
            log.error("Terminating because the controller is not alive.")
            return
        try:
            self.controller.attach_stream(stream_id, circuit_id)
        # All possible errors by `attach_stream`:
        except (
            stem.InvalidRequest, stem.UnsatisfiableRequest,
            stem.OperationFailed
        ) as err:
            log.warning("Failed to attach stream because: %s", err)
        except Exception as err:
            log.warning("Failed to attach stream because: %s", err)


def module_call(queue, module, circ_id, socks_port,
                exit_desc, run_cmd_over_tor, destinations,
                target_host, target_port):
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
            # Any of these are exceptions are circuit connection errors that
            # shouldn't be logged at error level.
            except (socket.error, error.SOCKSv5Error,
                    socket.timeout, EOFError, ConnectionError) as err:
                log.warning("Error in `module_call` closure: %s", err)
            # Any other unexpected exception is logged at error level and
            # re-raised so the outer module_call handler sees it.
            except Exception as err:
                log.error(
                    "Error in `module_call` closure: %s", err, exc_info=True
                )
                raise
        return closure

    try:
        module(
            exit_desc=exit_desc,
            run_python_over_tor=run_python_over_tor_wrapper(queue, circ_id, socks_port),
            run_cmd_over_tor=run_cmd_over_tor,
            destinations=destinations,
            target_host=target_host,
            target_port=target_port
        )
    except KeyboardInterrupt:
        log.debug("Ignoring `KeyboardInterrupt`")
    except Exception as exc:
        # An exception here is something unexpected from the module itself.
        log.error("Exception: %s", exc, exc_info=True)
    finally:
        log.debug("Informing event handler that module finished.")
        # keep finished_streams consistent, regardless of whether the moodule
        # raised or not
        queue.put((circ_id, None))


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
        # Use plain Queue instead of Manager().Queue() to avoid spawning
        # a Manager subprocess that must be explicitly shut down.
        self.queue = multiprocessing.Queue()
        self.socks_port = socks_port
        self.exit_destinations = exit_destinations
        self.target_host = target_host
        self.target_port = target_port
        self.check_finished_lock = threading.Lock()
        self.already_finished = False
        self.finished_event = threading.Event()

        self.queue_thread = threading.Thread(target=self.queue_reader)
        self.queue_thread.daemon = True
        self.queue_thread.start()

    def queue_reader(self):
        """
        Read (circuit ID, sockname) tuples from invoked probing modules.

        These tuples are then used to attach streams to their corresponding
        circuits.
        """

        log.debug("Starting thread to read from IPC queue.")

        while True:
            if not self.controller.is_alive():
                log.error("Terminating because the controller is not alive.")
                self.stats.print_progress()
                self.check_finished()
                break

            try:
                item = self.queue.get()
                self.last_message = time.monotonic()
                # Sentinel value signals shutdown
                if item is None:
                    log.debug("IPC queue received shutdown signal.")
                    break
                circ_id, sockname = item
            except (EOFError, queue.Empty):
                log.debug("IPC queue terminated.")
                break

            # Over the queue, a module can either signal that it finished
            # execution (by sending (circ_id,None)) or that it is ready to have
            # its stream attached to a circuit (by sending (circ_id,sockname)).

            if sockname is None:
                log.debug("Closing finished circuit %s.", circ_id)
                if not self.controller.is_alive():
                    log.error("Terminating because the controller is not alive.")
                    self.stats.print_progress()
                    self.check_finished()
                    break
                try:
                    circ = self.controller.get_circuit(circ_id)
                    if (circ):
                        log.debug("Circuit %s is still active, closing...", circ_id)
                        self.controller.close_circuit(circ_id)
                except (stem.InvalidArguments, stem.InvalidRequest) as err:
                    log.debug("Could not close circuit because: %s", err)
                except (ValueError, stem.ControllerError) as err:
                    log.debug("Could not get circuit because: %s", err)
                except Exception as err:
                    log.debug("Exception while getting/closing circuit: %s!", err)

                self.stats.finished_streams += 1
                self.stats.print_progress()
                self.check_finished()
            else:
                log.debug("Read from queue: %s, %s", circ_id, str(sockname))
                port = int(sockname[1])
                self.attacher.prepare(port, circuit_id=circ_id)
                self.check_finished()

        self._close_queue()

    def check_finished(self):
        """
        Check if the scan is finished and if it is, signal completion.
        """

        # This is called from both the queue reader thread and the
        # main thread, but (if it detects completion) does things that
        # must only happen once.
        with self.check_finished_lock:
            if self.already_finished:
                return

            # Did all circuits either build or fail?
            circs_done = ((self.stats.failed_circuits +
                           self.stats.successful_circuits) ==
                          self.stats.total_circuits)

            # Was every built circuit attached to a stream?
            streams_done = (self.stats.finished_streams >=
                            (self.stats.successful_circuits -
                             self.stats.failed_circuits))

            log.debug("failedCircs=%d, builtCircs=%d, totalCircs=%d, "
                      "finishedStreams=%d",
                      self.stats.failed_circuits,
                      self.stats.successful_circuits,
                      self.stats.total_circuits,
                      self.stats.finished_streams)

            if circs_done and streams_done:
                self.already_finished = True
                self.finished_event.set()

            if not self.controller.is_alive():
                log.error("Terminating threads because controller isn't alive.")
                self.already_finished = True
                self.finished_event.set()

    def wait(self):
        """
        Wait for the scan to finish.
        """
        # Only the time since all circuits were requested counts.
        self.last_message = time.monotonic()
        # Nobody notifies us if the controller dies, so check that regularly.
        while not self.finished_event.wait(timeout=1):
            if not self.controller.is_alive():
                self.check_finished()
                break
            # A module process which hangs or was killed never reports back.
            if time.monotonic() - self.last_message >= IDLE_TIMEOUT:
                # All modules of a run share the statistics, so count the
                # circuits as failed and the module processes as finished,
                # or the next module would wait for them again.
                circuits = max(0, self.stats.total_circuits -
                               self.stats.failed_circuits -
                               self.stats.successful_circuits)
                self.stats.failed_circuits += circuits
                modules = max(0, self.stats.successful_circuits -
                              self.stats.failed_circuits -
                              self.stats.finished_streams)
                self.stats.finished_streams += modules
                log.warning("No message from a module process for %d seconds."
                            "  No longer waiting for %d circuit(s) and %d "
                            "module process(es).",
                            IDLE_TIMEOUT, circuits, modules)
                break

    def shutdown(self):
        """
        Clean up resources and shut down.
        """
        # Remove event listener first — scan is complete, no more events needed.
        # This prevents event callbacks from racing with resource cleanup.
        try:
            # This blocks forever if the controller died while one of our
            # event callbacks was waiting for a reply.
            if self.controller.is_alive():
                self.controller.remove_event_listener(self.new_event)
        except Exception:
            pass

        for proc in multiprocessing.active_children():
            log.debug(
                "Terminating remaining PID %d with name %s.",
                proc.pid, proc.name
            )
            proc.terminate()

        if hasattr(self.module, "teardown"):
            log.debug("Calling module's teardown() function.")
            self.module.teardown()

        log.info(self.stats)

        # Signal queue reader to stop
        try:
            self.queue.put(None)
        except Exception:
            pass

        self.queue_thread.join(timeout=5)
        if self.queue_thread.is_alive():
            log.warning("Thread reading from IPC queue did not terminate.")
            # Don't wait for the queue's feeder thread at exit, either.
            self.queue.cancel_join_thread()

    def _close_queue(self):
        """
        Close the multiprocessing queue to release resources.
        """
        try:
            self.queue.close()
        except Exception:
            pass
        try:
            self.queue.join_thread()
        except Exception:
            pass

    def new_circuit(self, circ_event):
        """
        Invoke a new probing module when a new circuit becomes ready.
        """

        self.stats.update_circs(circ_event)
        self.check_finished()

        if circ_event.status not in [CircStatus.BUILT]:
            return

        last_hop = circ_event.path[-1]
        exit_fpr = last_hop[0]
        log.debug("Circuit for exit relay \"%s\" is built.  "
                  "Now invoking probing module.", exit_fpr)

        run_cmd_over_tor = command.Command(self.queue,
                                           circ_event.id,
                                           self.socks_port)
        if not self.controller.is_alive():
            log.error("Error creating new circuit: controller not alive.")
            return
        exit_desc = get_relay_desc(self.controller, exit_fpr)
        if exit_desc is None:
            log.warning("Descriptor unavailable for %s; skipping circuit %s.",
                        exit_fpr, circ_event.id)
            try:
                self.controller.close_circuit(circ_event.id)
            except (stem.InvalidArguments, stem.InvalidRequest) as err:
                log.debug("Could not close circuit because: %s", err)
            except Exception as err:
                log.error("Error while closing circuit: %s!", err, exc_info=True)
            # Add this circuit to finished_streams so check_finished()
            # doesn't block waiting for a sentinel that will never arrive.
            self.queue.put((circ_event.id, None))
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
            self.target_port
        ))
        proc.daemon = True
        # A process which is forked while another thread is writing a log
        # message inherits the locked log stream and blocks as soon as it logs
        # a message itself.
        handlers = list(logging.getLogger().handlers)
        for handler in handlers:
            handler.acquire()
        try:
            proc.start()
        finally:
            for handler in handlers:
                handler.release()

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
                        "event: %s", str(stream_event))
            return

        log.debug("Adding attacher for new stream %s.", stream_event.id)
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
            log.warning("Received unexpected event %s.", str(event))
