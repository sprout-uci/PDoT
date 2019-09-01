if [ ! -d deps ] ; then
    echo "Please run get_deps.sh"
    exit 1
fi

pushd deps

if [ ! -d wolfssl ] || [ ! -d curl ] || [ ! -d sgx-ra-tls ] ; then
    echo "Please run get_deps.sh"
    exit 1
fi


pushd wolfssl
[ ! -f ./configure ] && ./autogen.sh
    # Add --enable-debug for debug build
    # --enable-nginx: #define's WOLFSSL_ALWAYS_VERIFY_CB and
    # KEEP_OUR_CERT. Without this there seems to be no way to access
    # the certificate after the handshake.
    # 
    # 2017-12-11: --enable-nginx also activates OPENSSLEXTRA. The later
    # includes symbols that clash with OpenSSL, i.e., wolfSSL and OpenSSL
    # cannot be linked into the same binary. --enable-opensslcoexists does
    # not seem to help in this case.
WOLFSSL_CFLAGS="-fPIC -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT"
CFLAGS="$WOLFSSL_CFLAGS" ./configure --prefix=$(readlink -f ../local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext || exit 1 # --enable-debug
make -j`nproc` || exit 1
make install || exit 1
    # Add -DDEBUG_WOLFSSL to CFLAGS for debug
pushd IDE/LINUX-SGX
make -f sgx_t_static.mk SGX_DEBUG=1 CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT" || exit 1
cp libwolfssl.sgx.static.lib.a ../../../local/lib
popd
popd


pushd curl
./buildconf
./configure --prefix=$(readlink -f ../local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --with-ssl # --enable-debug
make -j`nproc` || exit 1
make install || exit 1
popd


pushd sgx-ra-tls
make -f ratls-wolfssl.mk || exit 1
popd


popd

