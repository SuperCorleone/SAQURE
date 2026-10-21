
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-DENIAL_OF_SERVICE' defined
 ... done.



ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:    9
                               8
                               7
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2023-33202 TEASTORE BCLIBRARY_TEASTORE PEM-ENDPOINT_TEASTORE
        1: ATTACKER-CRAFTS-MALICIOUS-PEM-PAYLOAD TEASTORE PEM-PAYLOAD1 ASN1-STRUCTURE_TEASTORE CVE_2023_33202
        2: ATTACKER-SENDS-HTTP-POST-REQUEST-WITH-MALICIOUS-PEM HTTP-POST-REQUEST1 TEASTORE PEM-PAYLOAD1 PEM-ENDPOINT_TEASTORE CVE_2023_33202
        3: APPLICATION-RECEIVES-HTTP-POST-REQUEST-WITH-MALICIOUS-PAYLOAD TEASTORE HTTP-POST-REQUEST1 PEM-PAYLOAD1 YAML-ENDPOINT_TEASTORE
        4: APPLICATION-EXTRACTS-PEM-PAYLOAD-FROM-HTTP-REQUEST TEASTORE HTTP-POST-REQUEST1 PEM-PAYLOAD1 PEM-ENDPOINT_TEASTORE
        5: APPLICATION-USES-BOUNCYCASTLE-PEMPARSER-READOBJECT TEASTORE BCLIBRARY_TEASTORE PEM-PAYLOAD1
        6: APPLICATION-PEMPARSER-ALLOCATES-HEAP-MEMORY-FOR-ASN1-CONSTRUCTION BCLIBRARY_TEASTORE PEM-PAYLOAD1 ASN1-STRUCTURE_TEASTORE TEASTORE
        7: APPLICATION-TRIGGERS-OUTOFMEMORY-ERROR TEASTORE CVE_2023_33202
        8: APPLICATION-BECOMES-UNRESPONSIVE TEASTORE
plan cost: 68.000000

time spent:    0.00 seconds instantiating 98 easy, 0 hard action templates
               0.00 seconds reachability analysis, yielding 27 facts and 11 actions
               0.00 seconds creating final representation with 27 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 12 states, to a max depth of 0
               0.00 seconds total time

