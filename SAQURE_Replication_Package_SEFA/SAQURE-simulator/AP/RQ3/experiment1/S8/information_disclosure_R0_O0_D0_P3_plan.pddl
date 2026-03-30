
ff: parsing domain file
domain 'ATTACK-PATH-PLANNER' defined
 ... done.
ff: parsing problem file
problem 'ELEVATE-PRIVILEGE-PROBLEM' defined
 ... done.


warning: operator APPLICATION-TOMCAT-JSP-ENGINE-PROCESSES-WEB-SHELL parameter ?HTTPGETREQUEST overwrites previous declaration


warning: operator USER-CLICKS-MALICIOUS-REDIRECT-URL-IN-MESSAGE parameter ?BROWSER overwrites previous declaration


warning: operator ATTACKER-CRAFTS-MALICIOUS-REDIRECT-URL-POINT-TO-PHISHINGSITE parameter ?APPLICATION overwrites previous declaration


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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2025-24813 SEFA TOMCAT_SEFA DEFAULT-SERVLET_SEFA SENSITIVE-FILE2_SEFA PUBLIC-DIRECTORY_SEFA SENSITIVE-DIRECTORY_SEFA
        1: ATTACKER-CRAFTS-HTTP-GET-REQUEST-WITH-INTERNAL-DOT-PATH-MANIPULATION HTTP-GET-REQUEST1 SENSITIVE-FILE2_SEFA PUBLIC-DIRECTORY_SEFA SENSITIVE-DIRECTORY_SEFA SEFA CVE_2025_24813
        2: ATTACKER-SENDS-MALICIOUS-HTTP-GET-REQUEST-TO-TOMCAT HTTP-GET-REQUEST1 SEFA TOMCAT_SEFA CVE_2025_24813
        3: APPLICATION-RECEIVES-HTTP-GET-REQUEST HTTP-GET-REQUEST1 SEFA
        4: APPLICATION-TOMCAT-DEFAULT-SERVLET-PROCESSES-REQUEST-WITHOUT-PROPER-VALIDATION HTTP-GET-REQUEST1 SEFA DEFAULT-SERVLET_SEFA TOMCAT_SEFA
        5: APPLICATION-TOMCAT-DEFAULT-SERVLET-INCORRECTLY-NORMALIZES-PATH HTTP-GET-REQUEST1 DEFAULT-SERVLET_SEFA TOMCAT_SEFA SEFA
        6: APPLICATION-TOMCAT-DEFAULT-SERVLET-ACCESSES-SENSITIVE-FILE SEFA HTTP-GET-REQUEST1 DEFAULT-SERVLET_SEFA SENSITIVE-FILE2_SEFA SENSITIVE-DIRECTORY_SEFA SENSITIVE-FILE-CONTENT2
        7: APPLICATION-SERVER-RETURNS-SENSITIVE-INFORMATION HTTP-GET-REQUEST1 SENSITIVE-FILE-CONTENT2 SEFA
        8: ATTACKER-RECEIVES-SENSITIVE-INFORMATION SEFA SENSITIVE-FILE-CONTENT2 CVE_2025_24813
plan cost: 10.000000

time spent:    0.05 seconds instantiating 4588 easy, 14 hard action templates
               0.00 seconds reachability analysis, yielding 284 facts and 292 actions
               0.00 seconds creating final representation with 281 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 96 states, to a max depth of 0
               0.05 seconds total time

