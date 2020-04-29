#!/bin/sh

ROOT_DIR=$PWD/..
EVAL_DIR=$ROOT_DIR/DoTS-experiment
PDOT_DIR=$ROOT_DIR/DoTS
GETDNS_RA_TLS_DIR=$ROOT_DIR/getdns-with-ratls

echo $ROOT_DIR
echo $EVAL_DIR
echo $PDOT_DIR
echo $GETDNS_RA_TLS_DIR

# Create bin directory that holds all the necessary applications
if [ ! -d "bin" ]; then
    cd $EVAL_DIR
    mkdir bin
fi

# Download Unbound and build it
if [ ! -d "unbound" ]; then
    cd $EVAL_DIR
    git clone https://github.com/NLnetLabs/unbound.git
    cd unbound
    git checkout release-1.8.0 # Stubby works with Unbound version 1.8.0
    ./configure
    make -j$(nproc)
    cp unbound $EVAL_DIR/bin/.
fi

# Download Stubby (for Unbound) and build it
if [ ! -d "getdns" ]; then
    cd $EVAL_DIR
    git clone https://github.com/getdnsapi/getdns.git
    cd getdns
    git submodule update --init
    mkdir build
    cd build
    cmake .. -DENABLE_STUB_ONLY=on -DBUILD_STUBBY=on -DUSE_LIBIDN2=off
    make -j$(nproc)
    cp stubby/stubby $EVAL_DIR/bin/unbound-stubby
fi

# Copy PDoT app and Stubby for PDoT to bin directory
cp $PDOT_DIR/src/App $EVAL_DIR/bin/.
cp $PDOT_DIR/src/Wolfssl_Enclave.signed.so $EVAL_DIR/bin/.
cp $GETDNS_RA_TLS_DIR/build/src/stubby $EVAL_DIR/bin/pdot-stubby