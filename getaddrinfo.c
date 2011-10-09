#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <GeoIP.h>


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
  if (errcode != 0)
    {
      perror ("getaddrinfo");
      return -1;
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
  return 0;
}

int getaddr (char *dom)
{   
  return lookup_host (dom);
}
