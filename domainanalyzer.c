#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <regex.h>
#include <GeoIP.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include "common.h"
#include "libdom.h"

#define MD5MAX (uint32_t) 32
#define SUCCESS (uint32_t) 0  

void usage(const char * p)
{
    fprintf(stderr, "domain analyzer: usage:%s domain/ip [-v]\n"
                    // get ASN && WLIST versions //
                    "version information:\n"
                        "\tASN:       %s\n"
                        "\tWhitelist: %s\n", p,
                        ASN_VERSION, WHITELIST_VERSION);
}

int main(int argc, char *argv[])
{
    int verbose = 0;
    char asnver[MD5MAX], wlistver[MD5MAX];
    memset(asnver, 0, sizeof(asnver));
    memset(wlistver, 0, sizeof(wlistver));
    
    if((argc != 2) && (argc != 3))
    {
        usage(argv[0]);
        return -1;
    }

    char * host;

    // too lazy for getopt
    if (argc == 3)
    {
        if (0 == strcmp(argv[1], "-v")) 
        {
            host = argv[2];
            verbose = 1;
        } 
        else if (0 == strcmp(argv[2], "-v"))
        {
            host = argv[1];
            verbose = 1;
        }
        else
        {
            usage(argv[0]);
            return -1;
        }
    }
    else 
    {
        host = argv[1];
    }
         
    // check if host is alive //
    struct hostent *server;
        
    server = gethostbyname(host);
    if (server == NULL)
    {
        fprintf(stderr, "%s: no such host\n", host);
        return -1;
    }

    int restatus=0;
    char * ASNBUFFER, * ASNDETAILS;
        
    // verify white lists first //
    if((restatus=check_whitelist(host)) == 0)
    {
        printf("%s is in white list\n", host);
        return 0;
    }
    else
    {
        printf("%s not detected in white list.\n", host);
    }
        
    // calling ASN RESOLVER //
    restatus=get_asn(host, &ASNBUFFER, &ASNDETAILS);
    if(restatus < 0)
    {
        fprintf(stderr, "ASN resolver failed");
    }
    else
    {
        printf("ASN=%s %s\n", ASNBUFFER, ASNDETAILS);
        free(ASNDETAILS);
    }
    // verify black asn lists first //
    restatus=check_asn(ASNBUFFER);
    free(ASNBUFFER);

    if(restatus == 0)
    {
        printf("*** ASN %s in black list! ***\n", ASNBUFFER);
        return 0;
    }
    else if (restatus > 0)
    {
        printf("ASN not detected as black.\n");
    }
    else
    {
        fprintf(stderr, "Cannot determine ASN status.\n");
    }

    char * cc = get_cc_from_domain(host);
    if (cc)
    {
        printf("Country:%s\n", cc);
        free(cc);
    }
    else
    {
        fprintf(stderr, "Oops, failed to retrieve CC\n");
    }

    int rc = check_home(host, verbose);
    if (rc < 0)
    {
        fprintf(stderr, "Failed retrieving home page for %s\n", host);
    }
    else if (rc > 0)
    {
        printf("Host %s does not match known signatures\n", host);
    }

    return rc;
}

