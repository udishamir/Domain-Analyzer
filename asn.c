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

int ASN (char *DOMBUFFER, char *ASNDETAILS, char *DOM) 
{
	GeoIP *gi;
  char *org;

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
