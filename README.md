# Enc Logs
This is a program for encrypting logs with a password made in C.
Works like a diary.
## Usage
For setting up, refer to [this](#setup) section.  
At first execution, the program will ask you for a password and to confirm it. (on the next runs, the program will ask you to enter the password again)  
After that, you enter the Command Line Interface (CLI) and you can use the following commands:
- 'help' to see the list of commands and their usage
- 'list' to list all the logs
- 'add' to add a new log
- 'remove' to remove a log
- 'passwd' to change the password
- 'wipe' to wipe all the logs
- 'exit' to exit the program
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
- the encrypted log data (content length, content and the timestamp)

For example:
If we have a log with the content "Hello World" and timestamp is "2019-01-01 00:00:00" the serialized log would look like this:
```
[length of "Hello World" in 4 bytes]["Hello World" without '\0'][timeval struct for "2019-01-01 00:00:00"]
```

And after being encrypted, it will be stored like this:
```
[length of encrypted log][encrypted log]
```

So the entire enclog file would look like this:
```
[signiture][n in 4 bytes][length of encrypted log 1][encrypted log content 1][length of encrypted log 2][encrypted log content 2]... (repeated n times)
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