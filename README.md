# VMAP

A Vulnerability-Exploit desktop finder. [Demo video](https://streamable.com/t2uld).

![alt tag](https://image.ibb.co/nK2ppv/vmap.png)

## INSTALLATION

```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # Optional Nmap filter (Linux only)
```

```shell
qmake
# qmake CONFIG+=NONMAP                                                      Nmap filter disabled
# qmake LIBS+="-LPATH/lib -lcrypto -lssl" INCLUDEPATH+="PATH/include"       OpenSSL custom path (Linux)
# qmake LIBS+="-LPATH/lib -llibcrypto -llibssl" INCLUDEPATH+="PATH/include" OpenSSL custom path (Windows)
make
make install
```

Vmap use the [vulners](https://vulners.com/api/v3/) API.
