Make sure to have the Intel SGX [SDK, Driver and PSW](https://github.com/intel/linux-sgx) installed.
Before executing code once, run:
```sh
source ${sgx-sdk-install-path}/environment

#e.g.
source /opt/intel/sgxsdk/environment
```
You can run samples with:
```sh
make SGX_MODE=SIM
./app
```
NOTE: Make sure the the glasses' EC private key is in pkcs8 form!
```sh
openssl pkey -in <inputKey> -out <outputKey>
```