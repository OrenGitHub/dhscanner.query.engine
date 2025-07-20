from flask import Flask
from flask import request

import re
import json
import tempfile
import subprocess

from typing import Final, Optional

app = Flask(__name__)

EXECUTE_QUERY: Final[str] = 'swipl --quiet -f {PROLOG_FILE} -g main -g halt'

@app.route('/check', methods=['POST'])
def check():

    kb = request.form['kb']

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
    status = subprocess.run(
        EXECUTE_QUERY.format(PROLOG_FILE=prolog_filename),
        capture_output=True,
        shell=True
    )
    stdout_response = status.stdout.decode('utf-8')
    stderr_response = status.stderr.decode('utf-8')
    return f'stdout=({stdout_response}), stderr=({stderr_response})'

@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    return { 'healthy': True }
