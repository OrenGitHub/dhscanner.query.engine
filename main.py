from flask import Flask
from flask import request

import subprocess

from typing import Final

app = Flask(__name__)

EXECUTE_QUERY: Final[list[str]] = ['swipl', '--quiet', '-f', 'main.pl', '-g', 'main', '-g', 'halt']

def execute_query() -> str:
    status = subprocess.run(EXECUTE_QUERY, capture_output=True)
    return status.stdout.decode("utf-8")

@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    return { 'healthy': True }

@app.route('/check/<cve>', methods=['POST'])
def check(cve):

    # the client only sends the knowledge base (kb)
    # prolog file. the "utils" and actual cve
    # scanner alreay exist on the server
    kb_prolog_fl = request.files['source']

    # read prolog kb to memory
    kb = kb_prolog_fl.read()

    # persist to (temporary) file on server
    # TODO: this is awful ... this mechanism
    # should be changed ASAP ...
    with open('kb.pl', 'w') as fl:
        fl.write(kb.decode("utf-8"))

    # prepare the prolog cve query
    # by simply replacing the template
    # cve rule with the actual cve
    with open(f'cves/{cve}.txt') as fl:
        actual_cve = fl.read()

    with open('template.pl') as fl:
        program = fl.read()

    with open('main.pl', 'w') as fl:
        fl.write(program.replace('template_cve', actual_cve))

    # execute query and capture result
    result = execute_query()

    return f'>>> {result}'
