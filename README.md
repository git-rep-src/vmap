# VMAP

A Vulnerability-Exploit desktop finder.

![alt tag](https://image.ibb.co/nK2ppv/vmap.png)

## INSTALLATION

### BUILD

```shell
qt       >= 5.x
libcurl  >= 7.5
libxml++ >= 3.0 # Linux optional Nmap filter
```
```shell
qmake
qmake CONFIG+=NONMAP # Linux Nmap filter disabled
qmake LIBS+="-LCURL_PATH/lib -llibcurl" INCLUDEPATH+="CURL_PATH/include" # Windows libcurl path
make
make install
```
### PACKAGES

```shell
yaourt -S vmap # Archlinux
pacman -S vmap # Blackarch
```

Vmap use the [vulners](https://vulners.com/api/v3/) API.
