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

#include "update.h"
#include "common.h"
#include "libdoma.h"

#define MD5MAX (uint32_t) 32
#define SUCCESS (uint32_t) 0  

void usage(const char * p)
{
    fprintf(stderr, "domain analyzer: usage:\n%s domain/ip [-v]\n"
                                              "%s -u/--update\n"
                    // get ASN && WLIST versions //
                    "version information:\n"
                        "\tASN:       %s\n"
                        "\tWhitelist: %s\n", p, p,
                        ASN_VERSION, WHITELIST_VERSION);
}

int main(int argc, char *argv[])
{
    if((argc != 2) && (argc != 3))
    {
        usage(argv[0]);
        return -1;
    }

    char * host;
    int verbose = 0;    

    if ((0 == strcmp(argv[1], "-u")) || (0 == strcmp(argv[1], "--update")))
    {
        // TODO: this is quite ugly, maybe change or aleast hide (move from here)
        // get relative path to executable
        char download_path[256];
        strncpy(download_path, argv[0], sizeof(download_path));
        // find rightmost /
        int pos;
        for (pos = strlen(download_path)-1; pos >= 0 && download_path[pos] != '/'; pos--);
        // strip out file name from path
        download_path[++pos] = '\0';
        // update to domain analyzer directory
        return update(download_path);
    }

    // TODO: add getopt
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
    struct hostent * server = gethostbyname(host);
    if (server == NULL)
    {
        fprintf(stderr, "%s: no such host\n", host);
        return -1;
    }

    // verify white lists first //
    int restatus = check_whitelist(host);
    if (restatus == 0)
    {
        printf("%s is in white list\n", host);
        return 0;
    }
    else
    {
        printf("%s not detected in white list.\n", host);
    }
        
    // calling ASN RESOLVER //
    char * asn_name;
    char * asn_details;        

    restatus = get_asn(host, &asn_name, &asn_details);
    if(restatus < 0)
    {
        fprintf(stderr, "ASN resolver failed, status=%d\n", restatus);
    }
    else
    {
        printf("ASN=%s (%s)\n", asn_name, asn_details);
        free(asn_details);
        
        // verify black asn lists first //
        restatus = check_asn(asn_name);
    	if (restatus == 0)
    	{
        	printf("*** ASN %s in black list! ***\n", asn_name);
        	free(asn_name);
		return 0;
    	}
    	else if (restatus > 0)
    	{
        	printf("ASN not detected as black.\n");
    		free(asn_name);
	}
    	else
    	{
        	fprintf(stderr, "Cannot determine ASN status.\n");
		free(asn_name);
	}			
    }


    char * cc = get_cc_from_domain(host);
    if (cc)
    {
        printf("Country: %s\n", cc);
        free(cc);
    }
    else
    {
        fprintf(stderr, "Oops, failed to retrieve CC\n");
    }

    int rc;
    struct flux_entry * flux;
    rc = get_flux(host, &flux);
    if (rc < 0)
    {
        fprintf(stderr, "Cannot retrieve fast flux information\n");
    }
    else
    {
        struct flux_entry * current = flux;

        if (current->addr_str)
        {
            printf("Printing fast flux analysis for %s...\n", host);
        }

        int count = 0;
        for (; current->addr_str; ++current, ++count)
        {
            printf("\t%s", current->addr_str);
            free(current->addr_str);

            if (current->cc[0])
            {
                printf(" (%c%c)", current->cc[0], current->cc[1]);
            }

            printf("\n");
        }

        if (count > 1)
        {
            printf("%s is a suspected flux domain\n", host);
        }
        
        free(flux);
    }
    rc = check_home(host, verbose);
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
