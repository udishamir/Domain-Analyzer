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

#define SUCCESS (uint32_t) 0
#define FAILD -1  


static inline int lookup_host (const char *host)
{
  struct addrinfo hints, *res;
  int errcode;
  uint32_t isflux=0;
  char addrstr[100];
  void *ptr;
	GeoIP * gi;
	
  memset (&hints, 0, sizeof (hints));
  memset(addrstr, 0, sizeof(addrstr));
  
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  errcode = getaddrinfo (host, NULL, &hints, &res);
  if (errcode != SUCCESS)
    {
      perror ("getaddrinfo");
      return FAILD;
    }

  printf ("Flux INFO\n");
  while (res)
    {
      inet_ntop (res->ai_family, res->ai_addr->sa_data, addrstr, 100);

      switch (res->ai_family)
        {
        case AF_INET:
          ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
          break;
        case AF_INET6:
          ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
          break;
        }
      inet_ntop (res->ai_family, ptr, addrstr, 100);
      // init GeoIP //
      gi = GeoIP_new(GEOIP_STANDARD);
      	
      if((GeoIP_country_code_by_name(gi, addrstr)) == NULL)
      	{
      		printf("%s\n", addrstr);
      		return SUCCESS;
      	}
      else
      	{
      		printf ("%s:::%s\n", addrstr, GeoIP_country_code_by_name(gi, addrstr));
      		if(isflux > 0)
      			printf("\nMight be flux domain ...... *\n");
      	}
      res = res->ai_next;
      isflux=isflux++;
    }
	printf("--\n");
  return SUCCESS;
}

int getaddr (char *dom)
{   
  return lookup_host (dom);
}
