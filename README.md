### zkinject

zkinject or libzkinject is a linux elf framework/library written in C++ for zkz debugger. main goal of this project is to make instrumentation with elf binaries eazy.

libzkinject uses linux /proc file system and ptrace system call to interact with running processes. it also parses elf binaries and provides set of APIs to manipulate internal data structures.

Currently it provides (incomplete) APIs for Silvio text padding injection and userland hooks

This project is still in the early stage of development :)

Future plans
- Data segment injections
- Reverse text padding injection
- Userland hooks with ptrace
- Process image reconstruction
- note section infections
