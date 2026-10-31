#!/bin/bash

python3 -u server.py --port 53 --zonefile zones/dns.zone --csv queries.csv $@
