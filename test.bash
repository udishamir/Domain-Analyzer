#!/bin/bash

for items in `cat dom.txt`
do
	./domainanalyzer $items
done
