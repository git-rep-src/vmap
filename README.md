# VMAP

A Vulnerability-Exploit desktop finder.

![alt tag](https://image.ibb.co/nK2ppv/vmap.png)

## INSTALLATION

### BUILD

```shell
qt        >= 5.x
libcurlpp >= 0.8
libxml++  >= 3.0 # Optional Linux Nmap filter
```

```shell
# Linux
qmake
qmake CONFIG+=NONMAP # Nmap filter disabled

# Windows 
qmake LIBS+="-LOPENSSSL_PATH/lib -llibcrypto -llibssl" "-LCURLPP_PATH/lib -llibcurl -llibcurlpp"\
INCLUDEPATH+="OPENSSL_PATH/include" "CURLPP_PATH/include"

make
make install
```
### PACKAGE

```shell
# Archlinux
yaourt -S vmap

# Blackarch
pacman -S vmap
```

Vmap use the [vulners](https://vulners.com/api/v3/) API.
