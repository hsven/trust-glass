Make sure to have the Intel SGX [SDK, Driver and PSW](https://github.com/intel/linux-sgx) installed.
Before executing code once, run:
```sh
source ${sgx-sdk-install-path}/environment

#e.g.
source /home/hsven/sgxsdk/environment
```
You can run samples with:
```sh
make SGX_MODE=SIM
./app
```