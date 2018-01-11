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

FROM ubuntu:16.04

MAINTAINER Alton Jensen version: 0.1

RUN apt-get update && apt-get install -y libdb-dev libdb++-dev build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev libminiupnpc-dev libzmq3-dev git unzip wget
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#build from latest refactor12 branch code
RUN git clone https://github.com/Greg-Griffith/ECCoin.git && cd ECCoin/src/ && make -f makefile.unix

RUN mkdir /root/.eccoin/

CMD ["/ECCoin/src/ECCoind","-listen","-upnp"]
