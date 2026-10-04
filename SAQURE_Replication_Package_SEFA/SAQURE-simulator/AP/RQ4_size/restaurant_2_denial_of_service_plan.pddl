
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

Advancing to goal distance:   15
                               9
                               7
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2022-40150 SEFA JETTISON-LIBRARY_SEFA API-ENDPOINT_SEFA SOAP-ENDPOINT_SEFA
        1: ATTACKER-CRAFTS-MALICIOUS-JSON-PAYLOAD SEFA MALICIOUS-JETTISON-PAYLOAD1 SNAKEYAML-LIBRARY_SEFA CVE_2022_40150
        2: ATTACKER-SENDS-HTTP-POST-REQUEST-WITH-MALICIOUS-PAYLOAD SEFA HTTP-POST-REQUEST1 MALICIOUS-JETTISON-PAYLOAD1 SOAP-ENDPOINT_SEFA CVE_2022_40150
        3: APPLICATION-RECEIVES-HTTP-POST-REQUEST-WITH-MALICIOUS-PAYLOAD SEFA HTTP-POST-REQUEST1 MALICIOUS-JETTISON-PAYLOAD1 SOAP-ENDPOINT_SEFA
        4: APPLICATION-EXTRACTS-JSON-PAYLOAD-FROM-HTTP-REQUEST SEFA HTTP-POST-REQUEST1 MALICIOUS-JETTISON-PAYLOAD1 API-ENDPOINT_SEFA
        5: APPLICATION-USES-JETTISON-JSON-PARSER SEFA JETTISON-LIBRARY_SEFA MALICIOUS-JETTISON-PAYLOAD1
        6: APPLICATION-JETTISON-PARSER-ALLOCATES-HEAP-MEMORY-FOR-JSON-CONSTRUCTION JETTISON-LIBRARY_SEFA MALICIOUS-JETTISON-PAYLOAD1 SEFA
        7: APPLICATION-TRIGGERS-OUTOFMEMORY-ERROR SEFA CVE_2022_40150
        8: APPLICATION-BECOMES-UNRESPONSIVE SEFA
plan cost: 37.000000

time spent:    0.08 seconds instantiating 6749 easy, 95 hard action templates
               0.00 seconds reachability analysis, yielding 137 facts and 189 actions
               0.00 seconds creating final representation with 133 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 137 states, to a max depth of 0
               0.08 seconds total time

