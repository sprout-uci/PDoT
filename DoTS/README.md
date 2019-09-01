Download the necessary dependencies:

    ./get_deps.sh



Add Intel Attestation Service (IAS) credentials
    
    Copy IAS client certificate to: src/ias-client-cert.pem
    Copy IAS client key to: src/ias-client-key.pem
    Set SPID in deps/sgx-ra-tls/ra_tls_options.c



Build the various dependencies:

    ./build_deps.sh



Build the server:

    cd src
    make SGX_MODE=HW SGX_DEBUG=1



Run the server:

    src/App -s



Test connection to server using:

    openssl s_client -crlf -connect 127.0.0.1:11111



Test connection with SGX-supported Stubby:

    Copy the MRENCLAVE value that is printed when running src/App -s.
    Encode it using Base64 (for example, use this [site](https://cryptii.com/base64-to-hex)).
    Paste that to the stubby.yml in the simpledns directory.
    Change directory to getdns-with-ratls.
    Follow the configuration and build section of its README.
    Be sure to configure Stubby with --enable-sgx option.
    Change directory to simpledns.
    Run Stubby by using sudo stubby -C stubby.yml -l.
    Then run dig @127.0.0.1 bbc.com
