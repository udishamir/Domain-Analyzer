CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
LIBS=-lcurl -lGeoIP -lpcre -lssl -lcrypto
EXECUTABLE=domainanalyzer 
SOURCES=urlanalyzer-pcre.c asn.c chksum.c getaddrinfo.c 
OBJECTS=$(SOURCES:.c=.o)

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o: 
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)



