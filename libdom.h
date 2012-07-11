#ifndef _libdom_h_
#define _libdom_h_

#include "common.h"

struct server_headers
{
	long http_code;
	double clen;
	char *rurl;
	char *ctype;
};
    
struct httpbody
{
	size_t size;
	size_t len;
	char *bodydata;
};

const char * asn_version(void);
const char * whitelist_version(void);
int check_whitelist(IN const char * domain);
int get_asn (IN const char * domain, OUT char **asn, OUT char **asn_details);  
int check_asn (IN const char * asn_list);
int read_from_url(IN const char * domain, IN struct httpbody * data, IN OPTIONAL FILE * fp);
int check_home(IN const char * host, IN int verbose);
char * get_cc_from_domain(IN const char * domain);

#define ASN_VERSION (asn_version())
#define WHITELIST_VERSION (whitelist_version())

#endif
