# Enc Logs
This is a program for encrypting logs with a password made in C.
Works like a diary.
## Encryption Algorithm
The encryption algorithm is as specified in the description AES-256-CBC.
The key and iv are generated from the password's SHA256 hash.
**HOWEVER**, I wouldn't recommend using this program despite the security of the algorithm because **I DO NOT KNOW WHAT I'M DOING** and there are most likely some security holes in my usage of the openssl library.
## Setup
```console
$ mkdir obj
```
## Building
```console
$ make
```
## Running
```console
$ ./enclogs
```