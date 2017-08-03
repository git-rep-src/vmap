# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

## INSTALLATION

```shell
qt       >= 5.x
openssl  >= 1.1
# Optional for Nmap filter
libxml++ >= 3.0 
```
```shell
qmake 
make
make install

# Set disabled Nmap filter
qmake CONFIG+=NONMAP

# Set custom path to OpenSSL on Linux
qmake LIBS+="-LPATH\lib -lcrypto -lssl" INCLUDEPATH+="PATH\include"

# Set custom path to OpenSSL on Windows
qmake LIBS+="-LPATH\lib -llibcrypto -llibssl" INCLUDEPATH+="PATH\include"
```
