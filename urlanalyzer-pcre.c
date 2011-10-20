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
#include </usr/local/include/pcre.h> 

#include "asn.h"


#define DEFILE "def.conf"
#define KNOWN "wlist.conf"
#define ASNLIST "asn.conf"
#define OVECCOUNT (uint32_t) 30
#define MD5MAX (uint32_t) 32
#define MAX_MATCH	(uint32_t) 128
#define SUCCESS (uint32_t) 0  

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
		if(rc == 1)
			{
				return 0;
			}
		
	return 1;
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
						return 2;
					}
				
				if((fp=fopen(ASNLIST, "r")) == NULL)
					{
						return -1;
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
 	
 	return 3;
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
      	if((md5sum(asnver, ASNLIST)) == SUCCESS)
      			printf("ASN Ver::%s\n", asnver);
  
      	if((md5sum(wlistver, KNOWN)) == SUCCESS)
      		printf("WLIST Ver::%s\n", wlistver);
      		
      	exit(0);
      }

		 
		// check if domain is alive //
		struct hostent *server;
		
		server = gethostbyname(argv[1]);
    if (server == NULL)
    	{
        printf("no such host\n");
        exit(-1);
    	}

		int restatus=0;
		char ASNBUFFER[7], ASNDETAILS[64], regexp_format[MAX_MATCH];
		GeoIP * gi;
		// init //
  	gi = GeoIP_new(GEOIP_STANDARD);
		
		// initialize buffers //
		memset(ASNBUFFER, 0, sizeof(ASNBUFFER));
		memset(ASNDETAILS, 0, sizeof(ASNDETAILS));
		
		// verify white lists first //
		if((restatus=whitelist(argv[1])) == 0)
			{
				printf("domain is clean\n");
				exit(0);
			}
		else
			{
				printf("--\ndomain not detected in white list..\n");
			}
			
		// calling ASN RESOLVER //
		if((restatus=ASN(ASNBUFFER, ASNDETAILS, argv[1])) == -1)
			{
				printf("ASN resolver faild");
			}
		
		printf("--\nAsn:%s %s\n", ASNBUFFER, ASNDETAILS);
		if((GeoIP_country_code_by_name(gi, argv[1])) == NULL)
			{
				printf("Oops, faild to retrieve\n");
				//return 1;
			}
		else
			{
				printf("Country:%s\n", GeoIP_country_code_by_name(gi, argv[1]));
			}
		
		// verify black asn lists first //
		if((restatus=asnlist(ASNBUFFER)) == 0)
			{
				printf("* ASN in black list ... *\n");
				exit(0);
			}
		else
			{
				printf("ASN not detected as black..\n--\n");
			}
		// flux //	
		getaddr(argv[1]);
		
    CURL *handle, *curl_code;
    CURLcode res;
    FILE *fp;
    
    struct httpbody_structure data;
    struct server_headers server_t;
   
    char url[4096], filebuffer[1024];
    
    // fake user-agent //
    char *UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1;\
     WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729;\
     .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)";
    
    int sets_res=0;
    
    //  initialize //
    memset(&data, 0, sizeof(data));
    memset(url, 0, sizeof(url));
    
    handle = curl_easy_init();
    if(handle)
    	{
    		memset(url, 0, (uint32_t)4096);
        data.size = 1024;
        data.bodydata = malloc(data.size);
        snprintf(url, sizeof(url), "http://%s", argv[1]);
        // get url //
        curl_easy_setopt(handle, CURLOPT_URL, url);
        // send our user agent //
        curl_easy_setopt(handle, CURLOPT_USERAGENT, UserAgent);
				
				// get body //
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &data);
      	//
      	
        res = curl_easy_perform(handle);
       
        // server headers //  
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &server_t.http_code);
        curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &server_t.rurl);
        curl_easy_getinfo(handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &server_t.clen);
        curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &server_t.ctype);
        
        if(server_t.clen == -1)
        	{
        		printf("Server Content-Length: Oops faild\n");
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
        printf("Server response->%lu\n", server_t.http_code);
  			if(server_t.http_code > 207)
  				{
  					if(server_t.rurl != NULL)
  						{
  							printf("Server send redirect->:%s\n", server_t.rurl);
  							return 1;
  						}
  				}
  				
        printf("connection status: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(handle);
    	}
    else 
    	{
        printf("Error getting CURL handle\n");
        exit(-1);
    	}

    if (data.len > 0)
    	{
    		if((fp=fopen(DEFILE, "r")) == NULL)
    			{
    				perror("open def.conf");
    				exit(-1);
    			}
    		
    		memset(filebuffer, 0, sizeof(filebuffer));
    		while((fgets(filebuffer, sizeof(filebuffer), fp)) != NULL)
    		{
    			filebuffer[strlen(filebuffer)-1]='\0';
    			snprintf(regexp_format, sizeof(regexp_format), "\\b%s\\b", filebuffer);
    			// send patterns //
    			if((sets_res=find_sets(data.bodydata, regexp_format)) == 0)
    				{
    					printf("%s\n", url);
    					return 0;
    				}
    			else if(res == -1)
    			{
    				printf("faild, cannot compile pattern\n");
    				exit(-1);
    			}
    			memset(regexp_format, 0, sizeof(regexp_format));
    		}
    		printf("not in our body list\n");
    	} 
    	else
    	 {
        printf("No data returned\n");
    	 }
    	 
    free(data.bodydata);
    return 0;
}