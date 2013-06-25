#!/usr/bin/python

import sys

import libdoma

def analyze_domain(domain):
  # TODO: check domain is alive

  if 0 == libdoma.check_whitelist(domain):
    return "Whitelisted"

  res, asn_name, asn_details = libdoma.get_asn(domain)
  print("ASN: {name}, {details}".format(name=asn_name, details=asn_details))
  if 0 != res:
    print("Failed retrieving asn info for {domain}".format(domain=domain))
  else:
    res = libdoma.check_asn(asn_name)
    if 0 == res:
      return "ASN blacklisted"
    elif 0 < res:
      print("ASN not blacklisted")
    elif 0 > res:
      print("Failed retrieving asn blacklisting status for {domain}".format(domain=domain))

  cc = libdoma.get_cc_from_domain(domain)
  print("Country: {cc}".format(cc=cc))
  
  res, fluxes = libdoma.get_flux(domain)
  if res < 0:
    print("Failed retrieving flux addresses for {domain}".format(domain=domain))
  else:
    for flux in fluxes:
      print("Flux: {addr}, {cc}".format(addr=flux.addr_str, cc=flux.cc))
  if 2 < len(fluxes):
    print("Suspected flux domain")

  ch = libdoma.check_home(domain, False)
  if ch < 0:
    print("Failed retrieving home page for {domain}".format(domain=domain))
  elif ch > 0:
    print("Host {domain} does not match known signatures".format(domain=domain))
 
  return "Seems legit"

def main():
  libdoma.update('./')
  for domain in sys.argv[1:]:
    print("{domain}: {result}".format(domain=domain, result=analyze_domain(domain)))
  
if __name__ == "__main__":
  main()

#    restatus = get_asn(host, &asn_name, &asn_details);
#    if(restatus < 0)
#    {
#        fprintf(stderr, "ASN resolver failed, status=%d\n", restatus);
#    }
#    else {
#        printf("ASN=%s (%s)\n", asn_name, asn_details);
#        free(asn_details);
#        
#        // verify black asn lists first //
#        restatus = check_asn(asn_name);
#        free(asn_name);
#    }
#
#    if (restatus == 0)
#    {
#        printf("*** ASN %s in black list! ***\n", asn_name);
#        return 0;
#    }
#    else if (restatus > 0)
#    {
#        printf("ASN not detected as black.\n");
#    }
#    else
#    {
#        fprintf(stderr, "Cannot determine ASN status.\n");
#    }
#
#    int rc;
#    struct flux_entry * flux;
#    rc = get_flux(host, &flux);
#    if (rc < 0)
#    {
#        fprintf(stderr, "Cannot retrieve fast flux information\n");
#    }
#    else
#    {
#        struct flux_entry * current = flux;
#
#        if (current->addr_str)
#        {
#            printf("Printing fast flux analysis for %s...\n", host);
#        }
#
#        int count = 0;
#        for (; current->addr_str; ++current, ++count)
#        {
#            printf("\t%s", current->addr_str);
#            free(current->addr_str);
#
#            if (current->cc[0])
#            {
#                printf(" (%c%c)", current->cc[0], current->cc[1]);
#            }
#
#            printf("\n");
#        }
#
#        if (count > 1)
#        {
#            printf("%s is a suspected flux domain\n", host);
#        }
#        
#        free(flux);
#    }
#}
