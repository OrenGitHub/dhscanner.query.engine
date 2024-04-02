from flask import Flask
from flask import request

import subprocess

from typing import Final

app = Flask(__name__)

COMPILE: Final[list[str]] = ["swipl", "-O", "-q", "--toplevel=main", "--stand_alone=true", "-o", "main", "-c", "main.pl" ]

EXECUTE_QUERY: Final[list[str]] = ['/main']

def compile_prolog_query() -> None:
    subprocess.run(COMPILE)

def execute_prolog_query() -> str:
    status = subprocess.run(EXECUTE_QUERY, capture_output=True)
    return status.stdout.decode("utf-8")

@app.route('/query/engine', methods=['POST'])
def query_engine():
    sent_prolog_fl = request.files['source']

    # read prolog program to memory
    prolog_query = sent_prolog_fl.read()

    # persist to (temporary) file on server
    with open('main.pl', 'w') as fl:
        fl.write(prolog_query.decode("utf-8"))

    # compile prolog query to native binary
    # all the filenames are hard coded
    # resulting binary name: main
    compile_prolog_query()

    # execute query and capture result
    result = execute_prolog_query()

    return f'>>> {result}'
