/* domainanalyzer, by udi shamir
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <GeoIP.h>
#include <errno.h>

#include "common.h"

int ASN (const char * domain, char **asn, char **asn_details) 
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
        fprintf(stderr, "Error opening database\n");
        return -EINVAL;
    }

    org = GeoIP_org_by_name (gi, domain);
    GeoIP_delete(gi);
    
    if (org == NULL)
    {
        return -ENOENT;
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
        return -ENOMEM;
    }

    *asn_details = strdup(ptr);
    if (!*asn_details)
    {
        free(*asn);
        return -ENOMEM;
    }

    return 0;
}
