# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

## INSTALL

```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # optional for nmap filter (load a nmap output xml file)
```

```shell
qmake
# set disabled nmap filter
qmake CONFIG+=NONMAP
# set custom path (openssl-linux)
qmake LIBS+="-LPATH\lib -lcrypto -lssl" INCLUDEPATH+="PATH\include"
# set custom path (openssl-windows)
qmake LIBS+="-LPATH\lib -llibcrypto -llibssl" INCLUDEPATH+="PATH\include" 
make
make install
```

