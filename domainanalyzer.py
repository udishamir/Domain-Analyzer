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
  if len(sys.argv) <= 1:
    print("Usage: {name} <domain #1> ... <domain #N>".format(name=sys.argv[0]))
    return

  libdoma.update('./')
  for domain in sys.argv[1:]:
    print("{domain}: {result}".format(domain=domain, result=analyze_domain(domain)))
  
if __name__ == "__main__":
  main()
