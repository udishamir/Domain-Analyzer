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

struct flux_entry
{
    char * addr_str;
    char cc[2];
};

const char * asn_version(void);
const char * whitelist_version(void);
int get_flux(const char * domain, struct flux_entry ** results);
void release_flux(struct flux_entry * flux);
int check_whitelist(IN const char * domain);
int get_asn (IN const char * domain, OUT char **asn, OUT char **asn_details);  
int check_asn (IN const char * asn_list);
int check_home(IN const char * host, IN int verbose);
char * get_cc_from_domain(IN const char * domain);
int update(char* download_path);

#define ASN_VERSION (asn_version())
#define WHITELIST_VERSION (whitelist_version())

#endif
