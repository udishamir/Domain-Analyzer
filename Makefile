CC=gcc
CFLAGS=-c -Wall -fpic
LDFLAGS=-shared -lc
LIBS=-lcurl -lGeoIP -lpcre -lssl -lcrypto
LIBDOM=libdom.so
EXECUTABLE=domainanalyzer
SOURCES=urlanalyzer-pcre.c asn.c chksum.c getaddrinfo.c 
OBJECTS=$(SOURCES:.c=.o)

E_LIBS=$(LIBDOM)
E_LDFLAGS=
E_SOURCES=domainanalyzer.c
E_OBJECTS=$(E_SOURCES:.c=.o)

all: $(SOURCES) $(LIBDOM) $(E_SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(E_OBJECTS) $(LIBDOM)
	$(CC) $(E_LDFLAGS) $(E_OBJECTS) $(E_LIBS) -o $@

$(LIBDOM): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o: 
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(LIBDOM) $(OBJECTS)



