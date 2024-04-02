### POC( Prolog Query Engine )

- A simple toy server to time compiled queries
- saves queries to disk, and meant to be run one query at a time ...

### Build and run the docker image
```bash
$ docker build --tag host.queryengine --file Dockerfile .
$ docker run -p 8030:5000 -d -t --name queryengine host.queryengine
$ docker exec -it queryengine bash # <--- to see what's going on ...

# inside docker ...
$ flask run --host 0.0.0.0

# from local machine outside docker
$ curl -X POST -F "source=@main.pl" http://127.0.0.1:8030/query/engine

# main.pl is not in this repo
# here is an (arbitrary) example
$ cat main.pl
edge(1,2).
edge(2,3).
edge(3,4).

connected(X,Y) :- edge(X,Y).
connected(X,Y) :- edge(X,Z), connected(Z,Y).

result(_) :- connected(1,_).
resultTag(_) :- connected(4,_).

main :- (result(_) -> write('yes\n') ; write('no\n')).
```