"""Does a process forked while another thread writes a log record hang at
its first log message?  usage: forklog.py file|stderr plain|locked N"""
import logging
import multiprocessing
import sys
import threading

target, mode, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
if target == "file":
    logging.basicConfig(filename="forklog.out", filemode="w",
                        level=logging.INFO)
else:
    logging.basicConfig(level=logging.INFO)
log = logging.getLogger("forklog")
stop = threading.Event()


def writer():
    while not stop.is_set():
        log.info("x" * 100)


def child():
    log.info("child")


threading.Thread(target=writer, daemon=True).start()
hung = 0
for i in range(n):
    proc = multiprocessing.Process(target=child)
    if mode == "locked":
        handlers = logging.getLogger().handlers
        for handler in handlers:
            handler.acquire()
        try:
            proc.start()
        finally:
            for handler in handlers:
                handler.release()
    else:
        proc.start()
    proc.join(timeout=3)
    if proc.is_alive():
        hung += 1
        proc.kill()
        proc.join()
stop.set()
print("%s %s: %d of %d children hung" % (target, mode, hung, n),
      file=sys.__stdout__)
