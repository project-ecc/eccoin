##################################  Notes  ##################################
# to build:
#   docker build --no-cache -t eccoind .
# (--no-cache is required or else it won't pull latest updates from github)
#
# to run:
#   docker run -p 19118:19118  eccoind
#
# to run with a mounted directory for ~/.eccoind:
#   docker run -p 19118:19118 -v /path/to/a/local/directory:/root/.eccoin eccoind
#
#############################################################################

FROM ubuntu:18.04

MAINTAINER Alton Jensen version: 0.2

RUN apt-get update && apt-get install -y libdb-dev libdb++-dev build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev libminiupnpc-dev libzmq3-dev git unzip wget
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#build from latest master branch code
RUN git clone https://github.com/project-ecc/eccoin.git && cd eccoin && ./autogen.sh && ./configure --with-incompatible-bdb && make


RUN mkdir /root/.eccoin/

CMD ["/eccoin/src/eccoind","-listen","-upnp"]
