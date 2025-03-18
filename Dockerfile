FROM python:3.12-slim AS builder

RUN apt-get update
RUN apt-get install -y wget
RUN apt-get install -y cmake
RUN apt-get install -y g++
RUN apt-get install -y build-essential
RUN apt-get install -y cmake
RUN apt-get install -y ninja-build
RUN apt-get install -y pkg-config
RUN apt-get install -y ncurses-dev
RUN apt-get install -y libreadline-dev
RUN apt-get install -y libedit-dev
RUN apt-get install -y libgoogle-perftools-dev
RUN apt-get install -y libgmp-dev
RUN apt-get install -y libssl-dev
RUN apt-get install -y unixodbc-dev
RUN apt-get install -y zlib1g-dev
RUN apt-get install -y libarchive-dev
RUN apt-get install -y libossp-uuid-dev
RUN apt-get install -y libxext-dev
RUN apt-get install -y libice-dev
RUN apt-get install -y libjpeg-dev
RUN apt-get install -y libxrandr-dev
RUN apt-get install -y libxinerama-dev
RUN apt-get install -y libxft-dev
RUN apt-get install -y libxpm-dev
RUN apt-get install -y libxt-dev
RUN apt-get install -y libdb-dev
RUN apt-get install -y libpcre2-dev
RUN apt-get install -y libyaml-dev
RUN apt-get install -y python3
RUN apt-get install -y libpython3-dev
RUN apt-get install -y default-jdk
RUN apt-get install -y junit4

RUN wget https://www.swi-prolog.org/download/stable/src/swipl-9.2.9.tar.gz
RUN tar -xf swipl-9.2.9.tar.gz
RUN cd swipl-9.2.9 && cmake . && make && make install

FROM python:3.12-slim AS runtime
COPY --from=builder /usr/local/bin/swipl /usr/local/bin/swipl
COPY --from=builder /usr/local/lib/swipl/ /usr/local/lib/swipl/
COPY --from=builder /lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libstdc++.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libtinfo.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgmp.so.10 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/

ENV LD_LIBRARY_PATH=/usr/local/lib/swipl/lib/x86_64-linux:/lib/x86_64-linux-gnu

RUN apt-get update
RUN apt-get install vim -y
RUN echo "set number" > ~/.vimrc
RUN echo "set incsearch" >> ~/.vimrc
RUN echo "syntax on" >> ~/.vimrc

RUN pip install flask
WORKDIR /queryengine
COPY . .
ENV FLASK_APP=main.py
EXPOSE 5000

CMD ["flask", "run", "--host", "0.0.0.0"]