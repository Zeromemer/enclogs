# Enc Logs
This is a program for encrypting logs with a password made in C.
Works like a diary.
## Encryption Algorithm
The encryption algorithm is as specified in the description AES-256-CBC.
The key and iv are generated from the password's SHA256 hash.
**HOWEVER**, I wouldn't recommend using this program despite the security of the algorithm because **I DO NOT KNOW WHAT I'M DOING** and there are most likely some security holes in my usage of the openssl library.
## Enclogs file format
The file starts with a signiture, which is in hex: 0xf3, 0x3f, 0x65, 0x6e, 0x63, 0x6c, 0x6f, 0x67, 0x73, 0x0d, 0x0a, 0x00  
The signiture is used to check if the file is a valid enclog file.
The next 4 bytes are the amount of logs in the file.  
each log is stored as follows:
- 4 bytes for the length of the log
- the encrypted log data (content length content and the timestamp)

for example:
if the log's content is "Hello World" and the timestamp is "2019-01-01 00:00:00" the serialized log would look like this:
```
[length of "Hello World" in 4 bytes]["Hello World"][timeval struct for "2019-01-01 00:00:00"]
```

and in the actual file it would look like this:
```
[length of encrypted log][encrypted log]
```

so the entire enclog file would look like this:
```
[signiture][1 in 4 bytes][length of encrypted log][encrypted log]
```

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