# VMAP

A Vulnerability-Exploit desktop finder. [Demo video](https://streamable.com/t2uld).

![alt tag](https://image.ibb.co/nK2ppv/vmap.png)

## INSTALLATION

```shell
qt        >= 5.x
libcurlpp >= 0.8
libxml++  >= 3.0 # OPTIONAL NMAP FILTER (LINUX ONLY)
```

```shell
qmake

# NMAP FILTER DISABLED
qmake CONFIG+=NONMAP 
# WINDOWS LIBRARY PATH
qmake LIBS+="-LOPENSSSL_PATH/lib -llibcrypto -llibssl" "-LCURLPP_PATH/lib -llibcurl -llibcurlpp"\
INCLUDEPATH+="OPENSSL_PATH/include" "CURLPP_PATH/include"

make
make install
```

Vmap use the [vulners](https://vulners.com/api/v3/) API.
