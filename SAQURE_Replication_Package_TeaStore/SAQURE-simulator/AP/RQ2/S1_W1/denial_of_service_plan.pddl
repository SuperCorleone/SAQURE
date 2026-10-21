
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-DENIAL_OF_SERVICE' defined
 ... done.



ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:   11
                              10
                               9
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2024-38809 TEASTORE SPRING-FRAMEWORK1 HTTP-ENDPOINT_TEASTORE ETAG-HANDLER_TEASTORE
        1: ATTACKER-CRAFTS-MALICIOUS-HTTP-REQUEST-WITH-PATHOLOGICAL-ETAG TEASTORE HTTP-POST-REQUEST1 ETAG-VALUE_TEASTORE CVE_2024_38809
        2: ATTACKER-OPENS-TCP-CONNECTION TEASTORE HTTP-POST-REQUEST1 TCP-CONNECTION_TEASTORE HTTP-ENDPOINT_TEASTORE
        3: APPLICATION-ACCEPTS-TCP-CONNECTION TEASTORE TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE HTTP-ENDPOINT_TEASTORE
        4: ATTACKER-SENDS-CRAFTED-HTTP-REQUEST-WITH-IF-MATCH-HEADER TEASTORE HTTP-POST-REQUEST1 TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE ETAG-VALUE_TEASTORE
        5: APPLICATION-RECEIVES-HTTP-REQUEST TEASTORE HTTP-POST-REQUEST1 TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE
        6: APPLICATION-SERVER-READS-HTTP-REQUEST-BYTES TEASTORE HTTP-POST-REQUEST1 TCP-CONNECTION_TEASTORE
        7: APPLICATION-EXTRACTS-IF-MATCH-HEADER-VALUE TEASTORE HTTP-POST-REQUEST1 ETAG-VALUE_TEASTORE HTTP-ENDPOINT_TEASTORE
        8: APPLICATION-CALLS-VULNERABLE-SPRING-ETAG-PARSING-ROUTINE TEASTORE SPRING-FRAMEWORK1 ETAG-VALUE_TEASTORE ETAG-HANDLER_TEASTORE
        9: APPLICATION-SUFFERS-RESOURCE-EXHAUSTION TEASTORE CVE_2024_38809 SPRING-FRAMEWORK1 ETAG-VALUE_TEASTORE
       10: APPLICATION-BECOMES-UNRESPONSIVE TEASTORE
plan cost: 73.000000

time spent:    0.00 seconds instantiating 221 easy, 1 hard action templates
               0.00 seconds reachability analysis, yielding 54 facts and 62 actions
               0.00 seconds creating final representation with 54 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 80 states, to a max depth of 0
               0.00 seconds total time

