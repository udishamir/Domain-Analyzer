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
#include <pcre.h> 

#include "asn.h"

#define DEFILE "def.conf"
#define KNOWN "wlist.conf"
#define ASNLIST "asn.conf"
#define OVECCOUNT (uint32_t) 30
#define MD5MAX (uint32_t) 32
#define MAX_MATCH  (uint32_t) 128
#define SUCCESS (uint32_t) 0  

// initial data to read from the wire for comparison and analysis
static const uint32_t DATA_SIZE = 1024;

// forward declarations (chksum.c)
int md5sum(char *hashsum, char *fname);
int getaddr (char *dom);

struct server_headers
{
	long http_code;
	double clen;
	char *rurl;
	char *ctype;
};
    
struct httpbody_structure
{
	size_t size;
	size_t len;
	char *bodydata;
};

int read_from_url(const char * domain, struct httpbody_structure * data);
char * get_cc_from_domain(const char * domain);

// fake user-agent //
static const char USER_AGENT[]="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1;\
                                WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729;\
                                .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)";

static const char HTTP_PROTO[] = "http://";
    

// search suspicious patterns //
int find_sets(char *respond_body, char *pattern)
{
    //printf(":::::::::%s:::::::::::\n", pattern);
    pcre *re;
    const char *error;
    int erroffset;
    int ovector[OVECCOUNT];
    int rc;
    
    re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
    if (! re)
    {    
        fprintf(stderr, 
            "PCRE compilation failed at expression offset %d: %s\n", erroffset, error); 
        return -1;
    }
    
    rc = pcre_exec(re, NULL, respond_body, strlen(respond_body), 0, 0, ovector, OVECCOUNT);
    pcre_free(re);

    if(rc == 1)
    {
        return 0;
    }
    else 
    {
        return 1;
    }
} 

// libcurl buffer //
static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    struct httpbody_structure *wdi = userp;

    while(wdi->len + (size * nmemb) >= wdi->size)
    {
        /* check for realloc failing in real code. */
        wdi->bodydata = realloc(wdi->bodydata, wdi->size*2);
        wdi->size*=2;
     }

    memcpy(wdi->bodydata + wdi->len, buffer, size * nmemb);
    wdi->len+=size*nmemb;

    return size * nmemb;
}

// check ASN black list //
int asnlist(char *_asn)
{
    FILE *fp;
    int ismatch;
    char buffer[4096];
    char regexp_format[128];
    
    struct stat fstat;
    
    if((stat(ASNLIST, &fstat)) == -1)
    {
        printf("asn.conf does not exist giving up on asn black listings\n");
        return -ENOENT;
    }

    if((fp=fopen(ASNLIST, "r")) == NULL)
    {
        perror("open asn.conf");
        return -ENOENT;
    }
    
    memset(buffer, 0, sizeof(buffer));    
    memset(regexp_format, 0, sizeof(regexp_format));
    snprintf(regexp_format, sizeof(regexp_format), "\\b%s\\b", _asn);
    while((fgets(buffer, sizeof(buffer), fp)) != NULL)
    {    
        if((ismatch=find_sets(buffer, regexp_format)) == 0)
        {
            fclose(fp);
            return 0;
        }
     }
     fclose(fp);
     
     return -EINVAL;
}

// check white list //
int whitelist(char *_domain)
{
    FILE *fp;
    int ismatch;
    char buffer[4096];
    struct stat fstat;
    
    if((stat(KNOWN, &fstat)) == -1)
    {
        printf("wlist.conf does not exist giving up on white listings\n");
        return 2;
    }
    
    if((fp=fopen(KNOWN, "r")) == NULL)
    {
        return -1;
    }
    
    memset(buffer, 0, sizeof(buffer));    
    while((fgets(buffer, sizeof(buffer), fp)) != NULL)
    {    
        if((ismatch=find_sets(buffer, _domain)) == 0)
        {
            fclose(fp);
            return 0;
        }
     }
     fclose(fp);
     
     return 3;
}
    
int main(int argc, char *argv[])
{
    char asnver[MD5MAX], wlistver[MD5MAX];
    memset(asnver, 0, sizeof(asnver));
    memset(wlistver, 0, sizeof(wlistver));
    
    if(argc != 2)
    {
        printf("domain analyzer: usage:%s domain/ip\n", argv[0]);
        // get ASN && WLIST versions //
        if((md5sum(asnver, ASNLIST)) == SUCCESS) printf("ASN Ver::%s\n", asnver);
        if((md5sum(wlistver, KNOWN)) == SUCCESS) printf("WLIST Ver::%s\n", wlistver);

        return 0;
    }

    char * domain = argv[1];
         
    // check if domain is alive //
    struct hostent *server;
        
    server = gethostbyname(domain);
    if (server == NULL)
    {
        printf("no such host\n");
        return -1;
    }

    int restatus=0;
    char ASNBUFFER[7], ASNDETAILS[64], regexp_format[MAX_MATCH];
        // initialize buffers //
    memset(ASNBUFFER, 0, sizeof(ASNBUFFER));
    memset(ASNDETAILS, 0, sizeof(ASNDETAILS));
        
    // verify white lists first //
    if((restatus=whitelist(domain)) == 0)
    {
        printf("domain is clean\n");
        return 0;
    }
    else
    {
        printf("--\ndomain not detected in white list..\n");
    }
        
    // calling ASN RESOLVER //
    if((restatus=ASN(ASNBUFFER, ASNDETAILS, domain)) == -1)
    {
        printf("ASN resolver failed");
    }
    else
    {
        printf("--\nAsn:%s %s\n", ASNBUFFER, ASNDETAILS);
    }

    char * cc = get_cc_from_domain(domain);
    if (cc)
    {
        printf("Country:%s\n", cc);
        free(cc);
    }
    else
    {
        printf("Oops, failed to retrieve CC\n");
    }

    // verify black asn lists first //
    if((restatus=asnlist(ASNBUFFER)) == 0)
    {
        printf("* ASN in black list ... *\n");
        return 0;
    }
    else
    {
        printf("ASN not detected as black..\n--\n");
    }
    // flux //    
    getaddr(argv[1]);
    
    struct httpbody_structure data = {0};
   
    data.size = DATA_SIZE;
    data.bodydata = malloc(data.size);

    int rc = -1;

    if (0 > read_from_url(domain, &data))
    {
        goto cleanup; 
    }

    FILE *fp = fopen(DEFILE, "r");
    if (data.len > 0)
    {
        if(fp == NULL)
        {
            perror("open" DEFILE);
            goto cleanup; 
        }

        char filebuffer[1024] = {0};
        while ((fgets(filebuffer, sizeof(filebuffer), fp)) != NULL)
        {
            // ensure 0-termination
            filebuffer[sizeof(filebuffer)-1]='\0';

            snprintf(regexp_format, sizeof(regexp_format), "\\b%s\\b", filebuffer);
            // send patterns //
            int sets_res = find_sets(data.bodydata, regexp_format);
            if (sets_res == 0)
            {
                printf("%s\n",domain);
                break;
            }
            else if (sets_res == -1)
            {
                printf("failed, cannot compile pattern\n");
                goto cleanup;
            }
            memset(regexp_format, 0, sizeof(regexp_format));
        }
        printf("not in our body list\n");
    } 
    else
    {
        printf("No data returned\n");
    }

    rc = 0;

cleanup:
    free(data.bodydata);
    if (fp) fclose(fp);
    return rc;
}

int read_from_url(const char * domain, struct httpbody_structure * data)
{
    CURL * handle = NULL;
    CURLcode curl_res;
    struct server_headers server_t;
    int rc = -1;

    // 255 octets is max length for DNS domain 
    char url[255 + sizeof(HTTP_PROTO)];

    memset(url, 0, sizeof(url));
    if (snprintf(url, sizeof(url), "%s%s", HTTP_PROTO, domain) >= sizeof(url))
    {
        // domain is too long, punt
        return -1;
    }

    handle = curl_easy_init();
    if(!handle)
    {
        return -1;
    }
    
    // get url //
    curl_easy_setopt(handle, CURLOPT_URL, url);
    // send our user agent //
    curl_easy_setopt(handle, CURLOPT_USERAGENT, USER_AGENT);
                
    // get body //
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, data);
    
    curl_res = curl_easy_perform(handle);
    
    // server headers //  
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &server_t.http_code);
    curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &server_t.rurl);
    curl_easy_getinfo(handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &server_t.clen);
    curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &server_t.ctype);
    
    if(server_t.clen == -1)
    {
        printf("Server Content-Length: Oops failed\n");
    }
    else
    {
        printf("Server Content-Length:%G\n", server_t.clen);
    }

    if(server_t.ctype == NULL)
    {
        printf("Server Content-Type->empty\n");
    }
    else
    {
        printf("Server Content-Type->%s\n", server_t.ctype);
    }

    printf("Server curl_response->%lu\n", server_t.http_code);

    if((server_t.http_code > 207) && (server_t.rurl != NULL))
    {
        printf("Server send redirect->:%s\n", server_t.rurl);
        rc = 1;
    }
    else 
    {            
        printf("connection status: %s\n", curl_easy_strerror(curl_res));
        rc = 0;
    }
    
    curl_easy_cleanup(handle);
    return rc;
}

char * get_cc_from_domain(const char * domain)
{
    GeoIP * gi = GeoIP_new(GEOIP_STANDARD);

    char * result = NULL;
    const char * tmp_str = GeoIP_country_code_by_name(gi, domain);

    if (tmp_str)
    {
        result = strdup(tmp_str);
    }

    GeoIP_delete(gi);

    return result;
}
