# VMAP

A vulnerability-exploit desktop finder. Vmap use the [vulners](https://vulners.com/api/v3/) API.

## INSTALLATION

```shell
qt       >= 5.x
openssl  >= 1.1
libxml++ >= 3.0 # (Optional for Nmap filter)
```
```shell
qmake # CONFIG+=NONMAP (Set disabled Nmap filter)
make
make install
```
