
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-DENIAL_OF_SERVICE' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:   14
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
        1: ATTACKER-ESTABLISHES-TCP-CONNECTION-WITH-APPLICATION TEASTORE TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE TCP-ENDPOINT_TEASTORE CVE_2024_38809
        2: ATTACKER-CRAFTS-MALICIOUS-HTTP-REQUEST-WITH-PATHOLOGICAL-ETAG TEASTORE SMUGGLING-TRIGGER-REQUEST1 ETAG-VALUE_TEASTORE CVE_2024_38809
        3: ATTACKER-SENDS-CRAFTED-HTTP-REQUEST-WITH-IF-MATCH-HEADER TEASTORE SMUGGLING-TRIGGER-REQUEST1 TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE ETAG-VALUE_TEASTORE
        4: APPLICATION-RECEIVES-HTTP-REQUEST TEASTORE SMUGGLING-TRIGGER-REQUEST1 TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE
        5: APPLICATION-SERVER-READS-HTTP-REQUEST-BYTES TEASTORE SMUGGLING-TRIGGER-REQUEST1 TCP-CONNECTION_TEASTORE
        6: APPLICATION-EXTRACTS-IF-MATCH-HEADER-VALUE TEASTORE SMUGGLING-TRIGGER-REQUEST1 ETAG-VALUE_TEASTORE HTTP-ENDPOINT_TEASTORE
        7: APPLICATION-CALLS-VULNERABLE-SPRING-ETAG-PARSING-ROUTINE TEASTORE SPRING-FRAMEWORK1 ETAG-VALUE_TEASTORE ETAG-HANDLER_TEASTORE
        8: APPLICATION-SUFFERS-RESOURCE-EXHAUSTION TEASTORE CVE_2024_38809 SPRING-FRAMEWORK1 ETAG-VALUE_TEASTORE
        9: APPLICATION-BECOMES-UNRESPONSIVE TEASTORE
plan cost: 72.000000

time spent:    0.05 seconds instantiating 7680 easy, 98 hard action templates
               0.00 seconds reachability analysis, yielding 379 facts and 763 actions
               0.00 seconds creating final representation with 376 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.01 seconds building connectivity graph
               0.01 seconds searching, evaluating 170 states, to a max depth of 0
               0.07 seconds total time

