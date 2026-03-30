
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

Advancing to goal distance:    9
                               7
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2023-6378 SEFA LOGBACKLIB_SEFA LOGBACK-RECEIVER_SEFA TCP-ENDPOINT_SEFA
        1: ATTACKER-ESTABLISHES-TCP-CONNECTION-WITH-APPLICATION SEFA TCP-SERVER_SEFA TCP-CONNECTION_SEFA TCP-ENDPOINT_SEFA CVE_2023_6378
        2: ATTACKER-CRAFTS-MALICIOUS-SERIALIZED-PAYLOAD SEFA SERIALIZED-PAYLOAD1 CVE_2023_6378
        3: ATTACKER-SENDS-MALICIOUS-PAYLOAD-THROUGH-TCP TCP-CONNECTION_SEFA TCP-SERVER_SEFA SERIALIZED-PAYLOAD1 LOGBACK-RECEIVER_SEFA
        4: APPLICATION-RECEIVES-TCP-CONNECTION-AND-DATA SEFA LOGBACK-RECEIVER_SEFA TCP-CONNECTION_SEFA SERIALIZED-PAYLOAD1
        5: APPLICATION-LOGBACK-RECEIVER-EXTRACTS-SERIALIZED-PAYLOAD SEFA LOGBACK-RECEIVER_SEFA SERIALIZED-PAYLOAD1
        6: APPLICATION-LOGBACK-RECEIVER-DESERIALIZES-PAYLOAD SEFA LOGBACK-RECEIVER_SEFA SERIALIZED-PAYLOAD1
        7: APPLICATION-DESERIALIZATION-TRIGGERS-RESOURCE-EXHAUSTION SEFA LOGBACK-RECEIVER_SEFA CVE_2023_6378
plan cost: 36.000000

time spent:    0.05 seconds instantiating 6764 easy, 97 hard action templates
               0.00 seconds reachability analysis, yielding 302 facts and 546 actions
               0.00 seconds creating final representation with 299 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 102 states, to a max depth of 0
               0.05 seconds total time

