from flask import Flask
from flask import request

import os
import signal
import typing
import tempfile
import subprocess

app = Flask(__name__)

STDOUT_PART: typing.Final[int] = 0
STDERR_PART: typing.Final[int] = 1

QUERY_TIME_LIMIT_SECONDS: typing.Final[int] = 180

def swipl_cmd(prolog_filename: str) -> list[str]:
    return ['swipl', '--quiet', '-s', prolog_filename, '-g', 'main', '-t', 'halt']

@app.route('/check', methods=['POST'])
def check():

    kb = request.files['kb'].read().decode('utf-8')

    with tempfile.NamedTemporaryFile(suffix=".pl", delete=False) as f:
        kb_filename = f.name
        f.write(kb.encode('utf-8'))

    with open('template.pl', 'rt') as f:
        content = f.read()

    with tempfile.NamedTemporaryFile(suffix=".pl", mode='w', delete=False) as f:
        main_filename = f.name
        f.write(content.format(KNOWLEDGE_BASE=kb_filename))

    result = execute_query(main_filename)
    return result

# don't worry about the PROLOG_FILE - it's not user input
# pylint: disable=subprocess-run-check
def execute_query(prolog_filename: str) -> str:
    proc = subprocess.Popen(
        swipl_cmd(prolog_filename),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True
    )
    try:
        response = proc.communicate(timeout=QUERY_TIME_LIMIT_SECONDS)
        return f'stdout=({response[STDOUT_PART]}), stderr=({response[STDERR_PART]})'
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return 'stdout=(), stderr=(received subprocess.TimeoutExpired)'

@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    return { 'healthy': True }
