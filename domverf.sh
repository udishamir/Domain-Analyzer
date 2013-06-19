#!/bin/bash

for ips in `cat connect_host.txt`
do
	./domainanalyzer $ips
done
