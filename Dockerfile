##################################  Notes  ##################################
# to build:
#   docker build --no-cache -t eccoin .
# (--no-cache is required or else it won't pull latest updates from github)
#
# to run:
#   docker run -P eccoin
#
# to run with a mounted directory for ~/.eccoin:
#   docker run -P -v /path/to/a/local/directory:/root/.eccoin eccoin
#
#############################################################################

FROM ubuntu:18.04

MAINTAINER Alton Jensen version: 0.2

#install necessary packages
RUN apt-get update && apt-get install -y libdb-dev libdb++-dev build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev libminiupnpc-dev libzmq3-dev software-properties-common
RUN add-apt-repository ppa:bitcoin/bitcoin && apt-get update && apt-get install -y libdb4.8-dev libdb4.8++-dev
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#build from local copy of codebase
COPY . /eccoin/
RUN cd eccoin && ./autogen.sh && ./configure && make

#final prep work to run daemon
RUN mkdir /root/.eccoin/
EXPOSE 19118
CMD ["/eccoin/src/eccoind","-listen","-upnp"]
