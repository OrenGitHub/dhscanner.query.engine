from flask import Flask
from flask import request

import tempfile
import subprocess

from typing import Final

app = Flask(__name__)

EXECUTE_QUERY: Final[str] = 'swipl --quiet -f {PROLOG_FILE} -g main -g halt'

def execute_query(prolog_filename: str) -> str:
    status = subprocess.run(
        EXECUTE_QUERY.format(PROLOG_FILE=prolog_filename),
        capture_output=True,
        shell=True
    )
    return status.stdout.decode('utf-8')

@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    return { 'healthy': True }

@app.route('/check', methods=['POST'])
def check():

    kb_fl = request.files['kb']
    queries_fl = request.files['queries']

    kb = kb_fl.read()
    queries = queries_fl.readlines()

    with tempfile.NamedTemporaryFile(suffix=".pl", delete=False) as f:
        kb_filename = f.name
        f.write(kb)

    with tempfile.NamedTemporaryFile(suffix=".pl", mode='w', delete=False) as f:
        main_filename = f.name
        f.write(f':- [ \'{kb_filename}\' ].\n')
        f.write(':- [ \'/queryengine/utils\' ].\n\n')
        for i, query in enumerate(queries):
            str_query = query.decode("utf-8")
            query_with_path = str_query.replace(').', f', Path{i}).')
            f.write(f'q{i}(Path{i}) :- {query_with_path}\n')
        f.write('\n')
        f.write('queries([\n')
        f.write(',\n'.join([f'    q{i}(Path{i})' for i, _ in enumerate(queries)]))
        f.write(']).\n\n')
        f.write('main :-\n')
        f.write('    queries(QueryList),\n')
        f.write('    forall(\n')
        f.write('        member(Query, QueryList),\n')
        f.write('        (Query -> write(Query), write(\': yes\'), nl ; write(Query), write(\': no\'), nl)\n')
        f.write('    ).')

    result = execute_query(main_filename)
    return f'>>> {result}'
