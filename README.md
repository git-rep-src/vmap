# VMAP

A Vulnerability-Exploit desktop finder.

![alt tag](https://image.ibb.co/nK2ppv/vmap.png)

## INSTALLATION

### BUILD

```shell
qt         >= 5.x
libcurl    >= 7.5
# libxml++ >= 3.0 Optional Linux Nmap filter
```
Linux
```shell
qmake
# qmake CONFIG+=NONMAP Nmap filter disabled
```
Windows 
```shell
qmake LIBS+="-LCURL_PATH/lib -llibcurl" INCLUDEPATH+="CURL_PATH/include"
```
```shell
make
make install
```
### PACKAGES

Archlinux
```shell
yaourt -S vmap
```
Blackarch
```shell
pacman -S vmap
```

Vmap use the [vulners](https://vulners.com/api/v3/) API.
