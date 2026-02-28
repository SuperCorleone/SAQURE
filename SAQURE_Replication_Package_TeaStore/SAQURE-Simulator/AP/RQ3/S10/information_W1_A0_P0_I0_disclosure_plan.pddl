
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2025-24813 TEASTORE TOMCAT_TEASTORE DEFAULT-SERVLET_TEASTORE SENSITIVE-FILE1_TEASTORE PUBLIC-DIRECTORY_TEASTORE SENSITIVE-DIRECTORY_TEASTORE
        1: ATTACKER-CRAFTS-HTTP-GET-REQUEST-WITH-INTERNAL-DOT-PATH-MANIPULATION HTTP-GET-REQUEST1 SENSITIVE-FILE2_TEASTORE PUBLIC-DIRECTORY_TEASTORE SENSITIVE-DIRECTORY_TEASTORE TEASTORE CVE_2025_24813
        2: ATTACKER-SENDS-MALICIOUS-HTTP-GET-REQUEST-TO-TOMCAT HTTP-GET-REQUEST1 TEASTORE TOMCAT_TEASTORE CVE_2025_24813
        3: APPLICATION-RECEIVES-HTTP-GET-REQUEST HTTP-GET-REQUEST1 TEASTORE
        4: APPLICATION-TOMCAT-DEFAULT-SERVLET-PROCESSES-REQUEST-WITHOUT-PROPER-VALIDATION HTTP-GET-REQUEST1 TEASTORE DEFAULT-SERVLET_TEASTORE TOMCAT_TEASTORE
        5: APPLICATION-TOMCAT-DEFAULT-SERVLET-INCORRECTLY-NORMALIZES-PATH HTTP-GET-REQUEST1 DEFAULT-SERVLET_TEASTORE TOMCAT_TEASTORE TEASTORE
        6: APPLICATION-TOMCAT-DEFAULT-SERVLET-ACCESSES-SENSITIVE-FILE TEASTORE HTTP-GET-REQUEST1 DEFAULT-SERVLET_TEASTORE SENSITIVE-FILE2_TEASTORE SENSITIVE-DIRECTORY_TEASTORE SENSITIVE-FILE-CONTENT2
        7: APPLICATION-SERVER-RETURNS-SENSITIVE-INFORMATION HTTP-GET-REQUEST1 SENSITIVE-FILE-CONTENT2 TEASTORE
        8: ATTACKER-RECEIVES-SENSITIVE-INFORMATION TEASTORE SENSITIVE-FILE-CONTENT2 CVE_2025_24813
plan cost: 10.000000

time spent:    0.05 seconds instantiating 5401 easy, 101 hard action templates
               0.00 seconds reachability analysis, yielding 484 facts and 895 actions
               0.00 seconds creating final representation with 481 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 150 states, to a max depth of 0
               0.05 seconds total time

