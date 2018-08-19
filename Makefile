all : netFilter
	
netFilter: main.o
	g++ -g -o netFilter netFilter.o -lnetfilter_queue

main.o:
	g++ -g -c -o netFilter.o netFilter.cpp

clean:
	rm -f netFilter
	rm -f *.o

