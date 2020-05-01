#!/bin/bash

ROOT_DIR=$PWD/..
EVAL_DIR=$ROOT_DIR/DoTS-experiment
PDOT_DIR=$ROOT_DIR/DoTS
GETDNS_RA_TLS_DIR=$ROOT_DIR/getdns-with-ratls

# Create bin directory that holds all the necessary applications
if [ ! -d "bin" ]; then
    cd $EVAL_DIR
    mkdir bin
    cd bin
    mkdir -p etc/unbound
fi

# Create private key & certificate for Unbound
cd bin
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
openssl req -new -key private_key.pem -out signreq.csr -subj "/C=US/ST=CA/L=Earth/O=SPROUT/OU=IT/CN=www.example.com/emailAddress=email@example.com"
openssl x509 -req -days 365 -in signreq.csr -signkey private_key.pem -out certificate.pem
PUBKEY_HASH=$(openssl rsa -in public_key.pem -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)

cd $EVAL_DIR
# Download Unbound and build it
if [ ! -d "unbound" ]; then
    git clone https://github.com/NLnetLabs/unbound.git
    cd unbound
    git checkout release-1.8.0 # Stubby works with Unbound version 1.8.0
    ./configure --prefix=$EVAL_DIR/bin
    make -j$(nproc)
    cp unbound $EVAL_DIR/bin/.
fi

# Download Stubby (for Unbound) and build it
cd $EVAL_DIR
if [ ! -d "getdns" ]; then
    git clone https://github.com/getdnsapi/getdns.git
    cd getdns
    git submodule update --init
    mkdir build
    cd build
    cmake .. -DENABLE_STUB_ONLY=on -DBUILD_STUBBY=on -DUSE_LIBIDN2=off
    make -j$(nproc)
    cp stubby/stubby $EVAL_DIR/bin/unbound-stubby
fi

# Build PDoT app
cd $PDOT_DIR/src
source /opt/intel/sgxsdk/environment
make clean
make SGX_MODE=HW SGX_DEBUG=1
cp $PDOT_DIR/src/App $EVAL_DIR/bin/.
cp $PDOT_DIR/src/Wolfssl_Enclave.signed.so $EVAL_DIR/bin/.

# Build Stubby for PDoT
cd $GETDNS_RA_TLS_DIR/build
../configure --without-libidn --without-libidn2 --enable-stub-only --with-stubby --enable-sgx
make clean
make
cp $GETDNS_RA_TLS_DIR/build/src/stubby $EVAL_DIR/bin/pdot-stubby

# Print necessary information
cd $EVAL_DIR
sed -i "s;value:;value: $PUBKEY_HASH;" unbound-stubby-template.yml
echo "Run App in bin directory with -d and copy paste the MRENCLAVE value here:"
read MRENCLAVE
sed -i "s;value:;value: $MRENCLAVE;" pdot-stubby-template.yml