CC=gcc
CFLAGS=-c -Wall -fpic -I/usr/include/python2.7/

LDFLAGS=-shared -lc -L/usr/lib/
LIBS=-lcurl -lGeoIP -lpcre -lssl -lcrypto -lpython2.7
LIBDOMA=_libdoma.so
SOURCES=urlanalyzer-pcre.c asn.c chksum.c flux.c update.c libdoma_wrap.c
OBJECTS=$(SOURCES:.c=.o)

E_LDFLAGS=
E_LIBS=-ldoma
EXECUTABLE=domainanalyzer
E_SOURCES=domainanalyzer.c
E_OBJECTS=$(E_SOURCES:.c=.o)

all: $(SOURCES) $(LIBDOMA) $(E_SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(E_OBJECTS) $(LIBDOMA)
	sudo cp _libdoma.so /usr/lib/libdoma.so
	$(CC) $(E_LDFLAGS) $(E_OBJECTS) $(E_LIBS) -o $@

$(LIBDOMA): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

libdoma_wrap.c: 
	swig -python -macroerrors -Wall -Werror libdoma.i

.c.o: 
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(LIBDOMA) $(OBJECTS) $(EXECUTABLE) $(E_OBJECTS) libdoma_wrap.c libdoma.py libdoma.so



