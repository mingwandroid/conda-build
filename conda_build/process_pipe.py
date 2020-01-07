from os import unlink
from subprocess import Popen, PIPE
from threading import Thread
try:
    from queue import Queue
except ImportError:
    from Queue import Queue  # python 2.x
import sys
from collections import OrderedDict

def reader(pipe, queue):
    try:
        with pipe:
            for line in iter(pipe.readline, b''):
                queue.put((pipe, line))
    finally:
        queue.put(None)


def _setup_process_pipes(process_stdout, process_stderr, rewrite_env = None,
                         log_file = None, log_stdout_file = None, log_stderr_file = None):
    # A dict to collect all necessary information:
    logged_rewriter = {}
    if not rewrite_env and not log_file and not log_stdout_file and not log_stderr_file:
        return logged_rewriter
    logged_rewriter['process_stdout'] = process_stdout
    logged_rewriter['process_stderr'] = process_stderr
    q = Queue()
    Thread(target=reader, args=[process_stdout, q]).start()
    Thread(target=reader, args=[process_stderr, q]).start()
    log = None
    log_stdout = None
    log_stderr = None
    if log_file:
        log = open(log_file, 'ab+')
    if log_stdout_file:
        log_stdout = open(log_stdout_file, 'ab+')
    if log_stderr_file:
        log_stderr = open(log_stderr_file, 'ab+')
    logged_rewriter['log'] = log
    logged_rewriter['log_stdout'] = log_stdout
    logged_rewriter['log_stderr'] = log_stderr
    logged_rewriter['queue'] = q
    replacements = OrderedDict()
    replacement_t = '%{}%' if sys.platform == 'win32' else '${}'
    if rewrite_env:
        for k, v in sorted(rewrite_env.items(), key=lambda kv: len(kv[1]), reverse=True):
            k = replacement_t.format(str(k)).encode('utf-8')
            v = v.encode('utf-8')
            replacements[v] = k
    logged_rewriter['replacements'] = replacements
    return logged_rewriter


def rewrite_and_log_process(logged_rewriter):
    OUTCOL = '\033[92m'
    ERRCOL = '\033[91m'
    ENDCOL = '\033[0m'
    if 'queue' not in logged_rewriter:
        print("ERROR :: No queue nor process")
        sys.exit(-1)
    queue = logged_rewriter['queue']
    process_stdout = logged_rewriter['process_stdout']
    process_stderr = logged_rewriter['process_stderr']
    log = logged_rewriter['log']
    log_stdout = logged_rewriter['log_stdout']
    log_stderr = logged_rewriter['log_stderr']
    replacements = logged_rewriter['replacements']
    for _ in range(2):
        for source, line in iter(queue.get, None):
            for s, key in replacements.items():
                line = line.replace(s, key)
            if source == process_stdout:
                sys.stdout.write(OUTCOL + "{}".format(line.decode('utf-8')) + ENDCOL)
                if log:
                    log.write(line)
                if log_stdout:
                    log_stdout.write(line)
            elif source == process_stderr:
                sys.stderr.write(ERRCOL + "{}".format(line.decode('utf-8')) + ENDCOL)
                if log:
                    log.write(line)
                if log_stderr:
                    log_stderr.write(line)
    if log:
        log.close()
    if log_stdout:
        log_stdout.close()
    if log_stderr:
        log_stderr.close()

# 'C:\\msys32\\usr\\bin\\ls.exe'
log = 'C:\\Users\\rdonnelly\\print-stdout-stderr.log'
log_stdout = 'C:\\Users\\rdonnelly\\print-stdout-stderr.stdout.log'
log_stderr = 'C:\\Users\\rdonnelly\\print-stdout-stderr.stderr.log'
try:
    unlink(log)
except:
    pass
try:
    unlink(log_stdout)
except:
    pass
try:
    unlink(log_stderr)
except:
    pass
process = Popen(['C:\\Users\\rdonnelly\\print-stdout-stderr.exe'], stdout=PIPE, stderr=PIPE, bufsize=1)
rewrite_env = {'PERSON': 'world'}
logged_rewriter = _setup_process_pipes(process.stdout, process.stderr, rewrite_env, log, log_stdout, log_stderr)
rewrite_and_log_process(logged_rewriter)
