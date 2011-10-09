/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 2; tab-width: 2 -*- */
/* test-geoip-asnum.c
 *
 * Copyright (C) 2006 MaxMind LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <GeoIP.h>

static const char * _mk_NA( const char * p ){
 return p ? p : "N/A";
}

int ASN (char *DOMBUFFER, char *ASNDETAILS, char *DOM) 
{
	FILE *f;
	GeoIP *gi;
  char *org;
	int generate = 0;

	gi = GeoIP_open("GeoIPASNum.dat", GEOIP_STANDARD);

	if (gi == NULL)
	 {
		printf("Error opening database\n");
		return -1;
	 }

	org = GeoIP_org_by_name (gi, (const char *)DOM);
	if (org != NULL)
		{
			sscanf(org,"%s\t%s", DOMBUFFER, ASNDETAILS);
		}

	GeoIP_delete(gi);

	return 0;
}
