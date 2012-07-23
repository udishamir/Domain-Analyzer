#include <GeoIP.h>

#include "libdoma.h"

int find_sets(char * response_body, const char * pattern);

int get_asn (const char * domain, char ** asn, char **asn_details) 
{
    GeoIP *gi;
    char *org;

    if (!asn || !asn_details) 
    {
        return -1;
    }

    gi = GeoIP_open("GeoIPASNum.dat", GEOIP_STANDARD);
    if (gi == NULL)
    {
        return -1;
    }

    org = GeoIP_org_by_name (gi, domain);
    GeoIP_delete(gi);
    
    if (org == NULL)
    {
        return -1;
    }

    //
    // find allocation size for ASN and details
    int size = 0;

    char * ptr = org;
    while (*ptr != '\t' &&
           *ptr)
    {
        size++;
        ptr++;
    }

    *ptr = '\0';
    ptr++;

    *asn = strdup(org);
    if (!*asn)
    {
        return -1;
    }

    *asn_details = strdup(ptr);
    if (!*asn_details)
    {
        free(*asn);
        return -1;
    }

    return 0;
}  

// check ASN black list //
int check_asn(const char * _asn)
{
    FILE *fp;
    int ismatch;
    char buffer[4096];
    char regexp_format[128];
    struct stat fstat;
    
    if((stat(ASNLIST, &fstat)) == -1)
    {
        return -1;
    }

    if((fp=fopen(ASNLIST, "r")) == NULL)
    {
        return -1;
    }
    
    memset(buffer, 0, sizeof(buffer));    
    memset(regexp_format, 0, sizeof(regexp_format));
    snprintf(regexp_format, sizeof(regexp_format), "\\b%s\\b", _asn);
    int rc = 0;
    while((fgets(buffer, sizeof(buffer), fp)) != NULL)
    {    
        buffer[sizeof(buffer) - 1] = (char)'\0';
        ismatch = find_sets(buffer, regexp_format);
        
        if (ismatch < 0)
        {
            rc = -1;
            goto error; 
        }

        if(ismatch == 0)
        {
            fclose(fp);
            return 0;
        }
     }

     rc = 1;

 error:
     fclose(fp);
     return rc;
}

// check white list //
int check_whitelist(const char * _domain)
{
    FILE *fp;
    int ismatch;
    char buffer[4096];
    struct stat fstat;
    
    if((stat(KNOWN, &fstat)) == -1)
    {
        return -1;
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
     
     return 1;
}
