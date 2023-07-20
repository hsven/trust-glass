# TrustGlass

## Introduction

TrustGlass is a custom protocol that connects a user to a remote service via a trusted path.
It leverages AR smart glasses, to enable the user to be a trusted path’s endpoints, and a TEE’s security assurances. 
As such, data can be securely exchanged between both endpoints with the necessary cryptographic operations.

TrustGlass was developed in the context of a master's thesis at Instituto Superior Técnico, Lisbon.

## Prerequisites

The enclave application is meant to function in a Linux environment. The OS used during development was Ubuntu 22.04.1 LTS. The system has not been tested in other OSes.

Make sure to have the [Intel SGX SDK, Driver and PSW](https://github.com/intel/linux-sgx) and [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl) installed.

Python and Django 4.2 are necessary if its planned to run the demonstration application.

Before executing any enclave code, run:
```sh
source ${sgx-sdk-install-path}/environment

#e.g.
source /opt/intel/sgxsdk/environment
```

## Using TrustGlass

TrustGlass is offered as a trusted library that can be used in an Intel SGX enclave application, accompanied by an Android application responsible for decrypting TrustGlass messages, used in the smart glasses.

To use the trusted library, visit its [README]() for details on how to implement it in an existing enclave application.

The Android application, while meant to be used with smart glasses, can be used in an Android smartphone.
[Android Studio](https://developer.android.com/studio) is recommended to build and setup the application.

## TrustGlass Demonstration Application

### Running the TrustGlass demo

An application that implements a small subset of ATM operations is included to try out TrustGlass.
This application consists of a Django python frontend and the enclave as the backend. 

0. Make sure the requisites are met.

1. Open a terminal and build the enclave
```sh
cd WebApp/EnclaveApp/
make SGX_MODE=SIM
```

2. Run the enclave
```sh
./app
```

3. In a new terminal, run the frontend
```sh
cd WebApp/
python manage.py runserver
```

4. You can now access the frontend page at [localhost:8000/home](localhost:8000/home)

5. In Android Studio, install the TrustGlass GlassesApp on your Android device.

6. Launch TrustGlass on your Android device. Be sure to give the application camera permissions for it to function.

### Usage

In the Android application, press 'Start Test' to activate the QR code scans.
Afterwards, simply point the camera to the QR code presented by the web app, and follow the instructions rendered by the Android device.

Press the back button on your Android device to scan the next QR code.