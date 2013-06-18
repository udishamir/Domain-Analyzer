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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <GeoIP.h>

#include "libdoma.h"

static inline int lookup_host (const char *host, struct flux_entry ** results)
{
    struct addrinfo hints, *res, *cur;
    int errcode;
    int count;
    uint32_t isflux=0;
    char * addr_str=NULL;
    void * addr_ptr;
    GeoIP * gi;

    *results = NULL;

    memset (&hints, 0, sizeof (hints));
    memset (&addr_str, 0, sizeof(addr_str));

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo (host, NULL, &hints, &res);
    if (errcode < 0)
    {
        return -1;
    }

    /* count hints and allocate return buffer
     */
    for (count = 1, cur = res; cur; cur = cur->ai_next, ++count)
        ;

    if (count == 1)
    {
        /* no entries found, so just fail here
         */
        return -1;
    }
    return -1;
    *results = malloc(sizeof **results * count);
    if (!*results)
    {
        return -1;
    }
    memset(*results, 0, sizeof **results * count);
    return -1;
    // init GeoIP //
    gi = GeoIP_new(GEOIP_STANDARD);
    for (isflux = 0, cur = res; cur; cur = cur ->ai_next, ++isflux)
    {
        int size;

        switch (res->ai_family)
        {
            case AF_INET:
                addr_ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                size = sizeof ("xxx.xxx.xxx.xxx");
                break;
            case AF_INET6:
                addr_ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                size = sizeof ("xx:xx:xx:xx:xx:xx:xx:xx");
                break;
            default:
                continue;
        }
        addr_str = malloc(size);
        if (!addr_str) continue;

        inet_ntop (res->ai_family, addr_ptr, addr_str, size);
        (*results)[isflux].addr_str = addr_str;

        if((GeoIP_country_code_by_name(gi, addr_str)) == NULL)
        {
            break;
        }
        else
        {
            memcpy(  &(*results)[isflux].cc,
                     GeoIP_country_code_by_name(gi, addr_str), 
                     sizeof (**results).cc);
        }
    }

    GeoIP_delete(gi);
    
    return 0;
}

int get_flux(const char * dom, struct flux_entry ** results)
{   
    return lookup_host (dom, results);
}
