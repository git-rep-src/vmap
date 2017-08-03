# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

## INSTALLATION

Dependencies
------------
```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # Optional for Nmap filter.
```

Build options
------------
### Set disabled Nmap filter 
qmake CONFIG+=NONMAP

### Set custom path to OpenSSL on Linux 
qmake LIBS+="-LPATH\lib -lcrypto -lssl" INCLUDEPATH+="PATH\include"

### Set custom path to OpenSSL on Windows 
qmake LIBS+="-LPATH\lib -llibcrypto -llibssl" INCLUDEPATH+="PATH\include"

Build 
------------
```shell
qmake 
make
make install
```

