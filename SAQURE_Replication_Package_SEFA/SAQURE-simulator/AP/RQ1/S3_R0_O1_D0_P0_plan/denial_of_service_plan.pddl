
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

Advancing to goal distance:    6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2024-38286 SEFA TOMCAT_SEFA TLS-CONNECTOR_SEFA
        1: ATTACKER-CRAFTS-TLS-FLOOD-SCRIPT SEFA TOMCAT-TLS-FLOOD-SCRIPT1 TOMCAT_SEFA CVE_2024_38286
        2: ATTACKER-INITIATES-TLS-FLOOD SEFA TOMCAT-TLS-FLOOD-SCRIPT1 TOMCAT_SEFA TLS-CONNECTOR_SEFA CVE_2024_38286
        3: APPLICATION-KEEPS-ALLOCATE-RESOURCES-FOR-HANDSHAKES TOMCAT_SEFA TLS-CONNECTOR_SEFA TOMCAT-TLS-FLOOD-SCRIPT1
        4: APPLICATION-TRIGGERS-OUTOFMEMORY-ERROR TOMCAT_SEFA SEFA
        5: APPLICATION-TOMCAT-CRASHES SEFA TOMCAT_SEFA
plan cost: 34.000000

time spent:    0.07 seconds instantiating 6797 easy, 105 hard action templates
               0.00 seconds reachability analysis, yielding 501 facts and 1344 actions
               0.00 seconds creating final representation with 498 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 125 states, to a max depth of 0
               0.07 seconds total time

