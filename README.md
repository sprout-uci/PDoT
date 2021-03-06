# Setting up your computer for SGX
## Follow the instructions stated in the [Intel SGX Installation Guide](https://download.01.org/intel-sgx/linux-2.1.3/docs/Intel_SGX_Installation_Guide_Linux_2.1.3_Open_Source.pdf).
The following shows the minimum instructions to get PDoT running.

```bash
sudo apt install libssl-dev libcurl4-openssl-dev libprotobuf-dev
sudo apt install alien
wget http://registrationcenter-download.intel.com/akdlm/irc_nas/11414/iclsClient-1.45.449.12-1.x86_64.rpm
sudo alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm
sudo dpkg -i iclsclient_1.45.449.12-2_amd64.deb
```
## Download and install the SGX driver, PSW, and SDK
The SGX driver, PSW, and SDK should be installed in the default locations. If installed in different locations, the `SGX_SDK` value in the `DoTS/src/Makefile` should be changed accordingly.

```bash
wget https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/sgx_linux_x64_driver_dc5858a.bin
wget https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/sgx_linux_x64_psw_2.2.100.45311.bin
wget https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/sgx_linux_x64_sdk_2.2.100.45311.bin
chmod +x sgx_linux_x64_*.bin
sudo ./sgx_linux_x64_driver_dc5858a.bin
sudo ./sgx_linux_x64_psw_2.2.100.45311.bin
sudo ./sgx_linux_x64_sdk_2.2.100.45311.bin #install under /opt/intel
source /opt/intel/sgxsdk/environment
```

 > If you have installed the SGX driver and PSW in the past and rebooted the machine, you will get an error saying: `The application could not create an enclave`. Follow the next steps to overcome this.
 > - First, uninstall the PSW by running `./uninstall.sh` in the PSW directory.
 > - Next, install the SGX driver by running the driver installer binary.
 > - Lastly, install SGX PSW by running the PSW installer binary.

# Building & Running PDoT

## Download the necessary dependencies:
```bash
sudo apt install build-essential libunbound-dev libssl-dev libtool m4 autoconf libyaml-dev cmake libexpat1-dev check python3-pip
pip3 install dnspython matplotlib numpy
cd DoTS
./get_deps.sh
```

## Add Intel Attestation Service (IAS) credentials
IAS credentials are required to run PDoT.
Obtain the credentials [here](https://api.portal.trustedservices.intel.com/EPID-attestation).
Sign up and subscribe to the `linkable` development access.
Click your name in the up-right corner and click `Manage Subscriptions`.
You will need `SPID` and `Primary key (EPID_SUBSCRIPTION_KEY)` for the credentials.

After collecting the credentials, run:
```bash
cd deps/sgx-ra-tls
SPID={} EPID_SUBSCRIPTION_KEY={} QUOTE_TYPE=SGX_LINKABLE_SIGNATURE bash ra_tls_options.c.sh > ra_tls_options.c
```
Replace `{}` with the credentials you obtained.

## Build the various dependencies:
```bash
cd ../../
./build_deps.sh
```

## Generate private key to sign Enclave:
```bash
cd src
openssl genpkey -algorithm RSA -out trusted/Wolfssl_Enclave_private.pem -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_keygen_pubexp:3
```

## Build the server:
```bash
make SGX_MODE=HW SGX_DEBUG=1
```

## Run the PDoT server:
```bash
./App -d # for normal use
./App -l # for latency evaluation
./App -t # for throughput evaluation
```
`V1`: Copy the value shown after the prompt `MRENCLAVE`.

> **NOTE:** If the server does not start, re-compile the server.
> ```bash
> make clean
> make SGX_MODE=HW SGX_DEBUG=1
> ```
> The authors have not found found other ways to overcome this.

## Stopping the server:
Press `Ctrl+C` to stop the server.

> If the server is not stopped using `Ctrl+C`, the server will not start normally next time.
> Follow the instruction show above to re-compile the server.

# Building Stubby with SGX support

## Gather dependencies
```bash
sudo apt install build-essential libunbound-dev libssl-dev libtool m4 autoconf
```

## Build & Run Stubby

### Users with root access
```bash
cd ../getdns-with-ratls
git submodule update --init
libtoolize -ci
autoreconf -fi
mkdir build
cd build
../configure --without-libidn --without-libidn2 --enable-stub-only --with-stubby --enable-sgx
make
sudo make install
```

### Users without root access
```bash
cd ../getdns-with-ratls
git submodule update --init
libtoolize -ci
autoreconf -fi
mkdir build
cd build
../configure --without-libidn --without-libidn2 --enable-stub-only --with-stubby --enable-sgx --prefix=[PATH_TO_INSTALL_LOCATION]
make
make install
```

## Change Stubby configuration file
Open `stubby.yml`. Copy-paste `MRENCLAVE` value `V1` you obtained when you ran DoTS to the location shown below.

```yml
############################ DEFAULT UPSTREAMS  ################################
####### IPv4 addresses ######
### Test servers ###
  - address_data: 127.0.0.1
    tls_port: 11111
    sgx_mr_enclave_set:
      - value: [PASTE_MRENCLAVE_VALUE_HERE]
```

## Run Stubby

### Users with root access
```bash
sudo ldconfig # To load the getdns library
sudo stubby -C stubby.yml
```

### Users without root access
Have a root user do the following for you:
```bash
sudo setcap 'cap_net_bind_service=+ep' /[PATH_TO_INSTALL_LOCATION]/stubby
```

Then run:
```bash
sudo ldconfig # To load the getdns library
./stubby -C stubby.yml
```

# Test Stubby & PDoT
Run the following.
```bash
dig @127.0.0.1 google.com
```

> If Stubby returns an error saying that the remote attestation cannot be done, re-compile the server.

# Run Experiments
`DoTS-experiments` directory includes scripts for running the experiments.

Follow the README file in that directory to conduct necessary experiments.