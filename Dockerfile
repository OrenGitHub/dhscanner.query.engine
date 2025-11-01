FROM haskell:9.6.7
WORKDIR /queryengine
COPY dhscanner.cabal dhscanner.cabal
RUN cabal update
RUN cabal build --only-dependencies
COPY src src
RUN cabal build
CMD ["cabal", "run"]