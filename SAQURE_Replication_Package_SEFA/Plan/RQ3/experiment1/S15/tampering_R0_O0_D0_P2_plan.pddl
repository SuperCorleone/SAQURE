
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-TAMPERING' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:   15
                              14
                              11
                               7
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2025-24813 SEFA TOMCAT_SEFA DEFAULT-SERVLET_SEFA SENSITIVE-FILE2_SEFA PUBLIC-DIRECTORY_SEFA SENSITIVE-DIRECTORY_SEFA
        1: ATTACKER-CREATES-MALICIOUS-CONTENT-FOR-INJECTION SEFA MALICIOUS-CONTENT1 SENSITIVE-FILE2_SEFA CVE_2025_24813
        2: ATTACKER-CRAFTS-HTTP-PUT-REQUEST-WITH-INTERNAL-DOT-PATH-MANIPULATION HTTP-PUT-REQUEST1 SENSITIVE-FILE2_SEFA PUBLIC-DIRECTORY_SEFA SENSITIVE-DIRECTORY_SEFA SEFA MALICIOUS-CONTENT1 CVE_2025_24813
        3: ATTACKER-INCLUDES-CONTENT-RANGE-HEADERS-FOR-PARTIAL-PUT HTTP-PUT-REQUEST1 CONTENT-RANGE-HEADERS1 SEFA CVE_2025_24813
        4: ATTACKER-SENDS-MALICIOUS-PARTIAL-HTTP-PUT-REQUEST-TO-TOMCAT HTTP-PUT-REQUEST1 CONTENT-RANGE-HEADERS1 SEFA TOMCAT_SEFA MALICIOUS-CONTENT1 CVE_2025_24813
        5: APPLICATION-RECEIVES-HTTP-PUT-REQUEST HTTP-PUT-REQUEST1 SEFA
        6: APPLICATION-TOMCAT-DEFAULT-SERVLET-PROCESSES-REQUEST-WITHOUT-PROPER-VALIDATION HTTP-PUT-REQUEST1 SEFA DEFAULT-SERVLET_SEFA TOMCAT_SEFA
        7: APPLICATION-TOMCAT-DEFAULT-SERVLET-INCORRECTLY-NORMALIZES-PATH HTTP-PUT-REQUEST1 DEFAULT-SERVLET_SEFA TOMCAT_SEFA SEFA
        8: APPLICATION-TOMCAT-DEFAULT-SERVLET-ACCESSES-SENSITIVE-FILE SEFA HTTP-PUT-REQUEST1 DEFAULT-SERVLET_SEFA SENSITIVE-FILE2_SEFA SENSITIVE-DIRECTORY_SEFA SENSITIVE-FILE-CONTENT2
        9: APPLICATION-TOMCAT-DEFAULT-SERVLET-WRITES-MALICIOUS-CONTENT-TO-SENSITIVE-FILE SEFA HTTP-PUT-REQUEST1 DEFAULT-SERVLET_SEFA SENSITIVE-FILE2_SEFA MALICIOUS-CONTENT1 CVE_2025_24813
plan cost: 11.000000

time spent:    0.06 seconds instantiating 6754 easy, 97 hard action templates
               0.00 seconds reachability analysis, yielding 233 facts and 170 actions
               0.00 seconds creating final representation with 229 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.01 seconds searching, evaluating 94 states, to a max depth of 0
               0.07 seconds total time

