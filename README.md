# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

## DEPENDENCIES

```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # Optional for Nmap filter(load a Nmap output XML file).
```

## BUILD OPTIONS

##### Set disabled Nmap filter #####
```shell
qmake CONFIG+=NONMAP
```
##### Set custom paths to OpenSSL on Linux #####
```shell
qmake LIBS+="-LPATH\lib -lcrypto -lssl" INCLUDEPATH+="PATH\include"
```
##### Set custom paths to OpenSSL on Windows #####
```shell
qmake LIBS+="-LPATH\lib -llibcrypto -llibssl" INCLUDEPATH+="PATH\include"
```

## BUILD & INSTALL

```shell
qmake 
make
make install
```

