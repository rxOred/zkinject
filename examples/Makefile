AS=nasm
CC=gcc
CPP=g++
ASFLAGS=-f elf64 -o
CPPFLAGS=-g -g3 -lzkinject -o

shellcode:
	${AS} ${ASFLAGS} shellcode shellcode.asm

hooking:
	${CPP} ${CPPFLAGS} hooking hooking.cc
