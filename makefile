#Makefile
#all:	1m-block
#1m-block: 
#		g++ -o 1m-block main.cpp -lnetfilter_queue -lsqlite3
#clean:
#		rm 1m-block


LDLIBS= -lnetfilter_queue -lsqlite3

all: 1m-block

1m-block: main.o db.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
		rm -f 1m-block *.o                        