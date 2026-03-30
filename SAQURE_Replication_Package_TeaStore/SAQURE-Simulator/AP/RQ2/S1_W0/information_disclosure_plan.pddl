
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-INFORMATION_DISCLOSURE' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2025-24813 TEASTORE TOMCAT_TEASTORE DEFAULT-SERVLET_TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE PUBLIC-DIRECTORY_TEASTORE SENSITIVE-DIRECTORY_TEASTORE
        1: ATTACKER-CRAFTS-HTTP-GET-REQUEST-WITH-INTERNAL-DOT-PATH-MANIPULATION HTTP-GET-REQUEST1 SENSITIVE-FILE2_TEASTORE PUBLIC-DIRECTORY_TEASTORE SENSITIVE-DIRECTORY_TEASTORE TEASTORE CVE_2025_24813
        2: ATTACKER-SENDS-MALICIOUS-HTTP-GET-REQUEST-TO-TOMCAT HTTP-GET-REQUEST1 TEASTORE TOMCAT_TEASTORE CVE_2025_24813
        3: APPLICATION-RECEIVES-HTTP-GET-REQUEST HTTP-GET-REQUEST1 TEASTORE
        4: APPLICATION-TOMCAT-DEFAULT-SERVLET-PROCESSES-REQUEST-WITHOUT-PROPER-VALIDATION HTTP-GET-REQUEST1 TEASTORE DEFAULT-SERVLET_TEASTORE TOMCAT_TEASTORE
        5: APPLICATION-TOMCAT-DEFAULT-SERVLET-INCORRECTLY-NORMALIZES-PATH HTTP-GET-REQUEST1 DEFAULT-SERVLET_TEASTORE TOMCAT_TEASTORE TEASTORE
        6: APPLICATION-TOMCAT-DEFAULT-SERVLET-ACCESSES-SENSITIVE-FILE TEASTORE HTTP-GET-REQUEST1 DEFAULT-SERVLET_TEASTORE SENSITIVE-FILE2_TEASTORE SENSITIVE-DIRECTORY_TEASTORE SENSITIVE-FILE-CONTENT2
        7: APPLICATION-SERVER-RETURNS-SENSITIVE-INFORMATION HTTP-GET-REQUEST1 SENSITIVE-FILE-CONTENT2 TEASTORE
        8: ATTACKER-RECEIVES-SENSITIVE-INFORMATION TEASTORE SENSITIVE-FILE-CONTENT2 CVE_2025_24813
plan cost: 10.000000

time spent:    0.06 seconds instantiating 6760 easy, 102 hard action templates
               0.00 seconds reachability analysis, yielding 446 facts and 960 actions
               0.00 seconds creating final representation with 443 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 140 states, to a max depth of 0
               0.06 seconds total time

