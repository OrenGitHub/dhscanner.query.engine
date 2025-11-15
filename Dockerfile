FROM haskell:9.6.7
WORKDIR /queryengine
RUN apt-get update
RUN apt-get install -y --no-install-recommends swi-prolog-nox
RUN rm -rf /var/lib/apt/lists/*
COPY dhscanner.cabal dhscanner.cabal
RUN cabal update
RUN cabal build --only-dependencies
COPY template.pl template.pl
COPY utils.pl utils.pl
COPY src src
RUN cabal build
CMD ["cabal", "run"]