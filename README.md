# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

![alt tag](https://image.ibb.co/nK2ppv/vmap.png)

## INSTALL

```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # optional Nmap filter (only Linux)
```

```shell
qmake
# qmake CONFIG+=NONMAP                                                      disabled Nmap filter
# qmake LIBS+="-LPATH/lib -lcrypto -lssl" INCLUDEPATH+="PATH/include"       custom path (OpenSSL-Linux)
# qmake LIBS+="-LPATH/lib -llibcrypto -llibssl" INCLUDEPATH+="PATH/include" custom path (OpenSSL-Windows)
make
make install
```

