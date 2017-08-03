# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

## INSTALLATION

```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # Optional for Nmap filter (load a Nmap output XML file).
```
```shell
qmake 
make
make install
```

* Set disabled Nmap filter:

		qmake CONFIG+=NONMAP

```shell
qmake CONFIG+=NONMAP
```
Set custom paths to OpenSSL on Linux
```shell
qmake LIBS+="-LPATH\lib -lcrypto -lssl" INCLUDEPATH+="PATH\include"
```
Set custom paths to OpenSSL on Windows
```shell
qmake LIBS+="-LPATH\lib -llibcrypto -llibssl" INCLUDEPATH+="PATH\include"
```
