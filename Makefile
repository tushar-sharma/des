CC=g++
CFLAGS=-I.

all: 
	mkdir -p bin
	g++ -I Lib/ src/des.cpp -o bin/des
