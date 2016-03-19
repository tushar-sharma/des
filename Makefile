CC=g++
CFLAGS=-I.

all:
	g++ -I Lib/ src/des.cpp -o bin/des
