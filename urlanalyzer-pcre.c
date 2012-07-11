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

#include "common.h"
#include "libdom.h"
#include "chksum.h"

#define MAX_MATCH  (uint32_t) 128

const char * asn_version()
{
    static int init = 0;
    static char version[100];

    if (!init) 
    {
        if (md5sum(version, ASNLIST) < 0)
        {
            strcpy(version, "<unknown>");
        }
        else
        {
            init = 1;
        }
    }

    return version;
}

const char * whitelist_version()
{
    static int init = 0;
    static char version[100];

    if (!init) 
    {
        if (md5sum(version, KNOWN) < 0)
        {
            strcpy(version, "<unknown>");
        }
        else
        {
            init = 1;
        }
    }

    return version;
}

#define OVECCOUNT (uint32_t) 30

// forward declarations (chksum.c)
int md5sum(char *hashsum, char *fname);

// fake user-agent //
static const char USER_AGENT[]="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1;\
                                WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729;\
                                .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)";

static const char HTTP_PROTO[] = "http://";  

// initial data to read from the wire for comparison and analysis
static const uint32_t DATA_SIZE = 1024;


// search suspicious patterns //
int find_sets(char *respond_body, char *pattern)
{   
    pcre *re;
    const char *error;
    int erroffset;
    int ovector[OVECCOUNT];
    int rc;
    
    re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
    if (!re)
    { 
        return -1;
    }
    
    rc = pcre_exec(re, NULL, respond_body, strlen(respond_body), 0, 0, ovector, OVECCOUNT);
    pcre_free(re);

    return (rc == 1)?0:1;
} 

// libcurl buffer //
static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    struct httpbody * wdi = userp;

    while (wdi->len + (size * nmemb) >= wdi->size)
    {
        /* check for realloc failing in real code. */
        wdi->bodydata = realloc(wdi->bodydata, wdi->size*2);
        wdi->size*=2;
    }

    memcpy(wdi->bodydata + wdi->len, buffer, size * nmemb);
    wdi->len+=size*nmemb;

    return size * nmemb;
}


int read_from_url(IN const char * domain, OUT struct httpbody * data, IN OPTIONAL FILE * fp)
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
        if (fp) fprintf(fp, "Content-Length: ???\n");
    }
    else
    {
        if (fp) fprintf(fp, "Content-Length: %G\n", server_t.clen);
    }

    if(server_t.ctype == NULL)
    {
        if (fp) fprintf(fp, "Content-Type is unset\n");
    }
    else
    {
        if (fp) fprintf(fp, "Content-Type: %s\n", server_t.ctype);
    }

    if (fp) fprintf(fp, "HTTP status: %lu\n", server_t.http_code);

    if((server_t.http_code > 207) && (server_t.rurl != NULL))
    {
        if (fp) fprintf(fp, "HTTP redirect -> %s\n", server_t.rurl);
        rc = 1;
    }
    else 
    {            
        if (fp) fprintf(fp, "Connection status: %s\n", curl_easy_strerror(curl_res));
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

int check_home(IN const char * host, IN int verbose)
{
    char regexp_format[MAX_MATCH];
    // flux //    
    struct httpbody data = {0};
   
    data.size = DATA_SIZE;
    data.bodydata = malloc(data.size);

    int rc = -1;
    if (0 > read_from_url(host, &data, verbose?stdout:NULL))
    {
        goto cleanup; 
    }

    FILE *fp = fopen(DEFILE, "r");
    if (data.len > 0)
    {
        if(fp == NULL)
        {
            rc = -1;
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
                rc = 0;
                break;
            }
            else if (sets_res == -1)
            {
                goto cleanup;
            }
            memset(regexp_format, 0, sizeof(regexp_format));
        }
        rc = 1;
    } 
    else
    {
        rc = -1;
    }

    rc = 0;

cleanup:
    free(data.bodydata);
    if (fp) fclose(fp);
    return rc;
}