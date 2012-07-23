CC=gcc
CFLAGS=-c -Wall -fpic
LDFLAGS=-shared -lc
LIBS=-lcurl -lGeoIP -lpcre -lssl -lcrypto
LIBDOMA=libdoma.so
EXECUTABLE=domainanalyzer
SOURCES=urlanalyzer-pcre.c asn.c chksum.c flux.c 
OBJECTS=$(SOURCES:.c=.o)

E_LIBS=$(LIBDOMA)
E_LDFLAGS=
E_SOURCES=domainanalyzer.c
E_OBJECTS=$(E_SOURCES:.c=.o)

all: $(SOURCES) $(LIBDOMA) $(E_SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(E_OBJECTS) $(LIBDOMA)
	$(CC) $(E_LDFLAGS) $(E_OBJECTS) $(E_LIBS) -o $@

$(LIBDOMA): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o: 
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(LIBDOMA) $(OBJECTS)



