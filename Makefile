# the compiler to use.
CC=gcc -Wall
CFLAGS=-O2 -o  
LIBS=-lcurl -lGeoIP -lpcre -lssl -lcrypto

domainanalyzer: 
	$(CC) $(CFLAGS) domainanalyzer urlanalyzer-pcre.c asn.c chksum.c getaddrinfo.c $(LIBS)

clean:
	rm -rf domainanalyzer


