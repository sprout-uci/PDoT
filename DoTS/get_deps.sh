# patch -p1 < src-ias-sgx-sim-mode.patch || exit 1

mkdir -p deps
pushd deps

if [ ! -d sgx-ra-tls ] ; then
    git clone https://github.com/cloud-security-research/sgx-ra-tls.git || exit 1
    pushd sgx-ra-tls
    patch -p1 < ../../sgx-ra-tls-deps.patch || exit 1
    popd
fi

if [ ! -d wolfssl ] ; then
    git clone https://github.com/wolfSSL/wolfssl || exit 1
    pushd wolfssl
    git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
    patch -p1 < ../sgx-ra-tls/wolfssl.patch || exit 1
    popd
fi

if [ ! -d curl ] ; then
    git clone https://github.com/curl/curl.git
    pushd curl
    git checkout curl-7_69_1
    popd
fi

#if [ ! -d linux-sgx ] ; then
#    git clone https://github.com/01org/linux-sgx.git
#    pushd linux-sgx
#    git checkout sgx_2.0
#    popd
#fi

popd

pushd src

cp ../deps/sgx-ra-tls/sgxsdk-ra-attester_u.c untrusted/.
cp ../deps/sgx-ra-tls/ias-ra.c untrusted/.
pushd untrusted
patch < ias-ra.patch || exit 1
popd

popd