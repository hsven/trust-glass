# TrustGlass Trusted Library

This trusted library implements the TEE-side functions necessary to establish a trusted path with the client-side.

# Setup

Make sure that the prerequisites, that is, 
[Intel SGX SDK, Driver and PSW](https://github.com/intel/linux-sgx) and [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl), are installed.

To use this trusted library in your enclave application, include its files in the makefile of the enclave.
Check the [makefile](/Demo/EnclaveApp/Makefile) of our demonstration application for an example.

# Usage
1. In your enclave's code, start by instancing a TrustGlass object:
```cpp
    TrustGlass* trustGlass = new TrustGlass();
```

2. Set up the long term shared key. This key should be encoded as Base64, and be the same as the key present in the Android application
```cpp
// Base64 key used for the demo
    const char* in = "W/EC20gaJJTuMGzqwIezjUeSdJhHh0VpiTWrZiHOUO3h4faUyy9ALcImwphBIFoawXDVfj2jti28    yjYAQJJcHMZwsRkx37iwO6sWL+6xPcF+bUuG3G174Itc2wV+7poGNH2D9q2umCLJC/l+6UdyTvjp    CBNd6EEkMk0SeJzp0MGNVn7zYcs7C6H7FhqwL9lP94Bl6nw7r8kHx9KPVQh+krlGzHmoc5Z+wIx4    qkQ61smpc4jsOcfWSzcIWXEbTM8LK8LZYF4g+jbKvZ/bbDhCX6U381eZhZ0y8yanC5B98Lw9QtRM    tV9Ge05XcHSA8jpMtngdo/+BIlRADwNuAWPGLg=="

    trustGlass->set_long_term_shared_key(in);
```

3. Start the session with the Android application. Be sure that the Android application reads the QR code result of encoding the output of this method.
```cpp
    char* response = trustGlass->do_session_start();
```

4. Request the user's authentication via their PIN.
```cpp
    char* response = trustGlass->do_pin_login();
```

5. With the user autheticated, they can start exchanging messages with TrustGlass. Before sending a message to the user, let TrustGlass process it.
```cpp
    std::string content = "Hello from TrustGlass!"
    //Empty keyboard map
    std::string map = "null";
    char* response = trustGlass->do_message(content, map);
```

All of TrustGlass' methods can be verified in its [header file](/TrustGlass_TEE/TrustGlass.h).