
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2024-22243 TEASTORE SPRING-FRAMEWORK1 URL-SETTING-ENDPOINT1 URICOMPONENTSBUILDER
        1: ATTACKER-CRAFTS-MALICIOUS-REDIRECT-URL-POINT-TO-INTERNAL-RESOURCE REDIRECT-URL1 VALIATION-PASS-PYLOAD1 INTERNAL-RESOURCE-ADDRESS1 TEASTORE CVE_2024_22243
        2: ATTACKER-CLICKS-MALICIOUS-URL-INCLUDES-INTERNAL-RESOURCES-REQUEST-PYLOAD BROWSER-CHROME REDIRECT-URL1 INTERNAL-RESOURCE-ADDRESS1
        3: ATTACKER-BROWSER-SENDS-MALICIOUS-HTTP-GET-REQUEST-FOR-INTERNAL-RESOURCES BROWSER-CHROME HTTP-GET-REQUEST1 REDIRECT-URL1 INTERNAL-RESOURCE-ADDRESS1
        4: APPLICATION-RECEIVES-HTTP-GET-REQUEST HTTP-GET-REQUEST1 TEASTORE
        5: APPLICATION-PROCESSES-HTTP-GET-REQUEST-BY-PARSER HTTP-GET-REQUEST1 REDIRECT-URL1 TEASTORE URICOMPONENTSBUILDER
        6: APPLICATION-VULNERABLY-VALIDATES-HOST-IN-URL TEASTORE REDIRECT-URL1 URICOMPONENTSBUILDER
        7: APPLICATION-SERVER-SENDS-INTERNAL-REQUEST REDIRECT-URL1 INTERNAL-RESOURCE-ADDRESS1 TEASTORE
        8: APPLICATION-INTERNAL-SERVER-RESPONDS-SENSITIVE-INFORMATION INTERNAL-RESOURCE-ADDRESS1 SENSITIVE-FILE-NAME1 TEASTORE
        9: APPLICATION-SERVER-RETURNS-SENSITIVE-INFORMATION HTTP-GET-REQUEST1 SENSITIVE-FILE-NAME1 TEASTORE
       10: ATTACKER-RECEIVES-SENSITIVE-INFORMATION TEASTORE SENSITIVE-FILE-NAME1 CVE_2024_22243
plan cost: 31.000000

time spent:    0.05 seconds instantiating 4622 easy, 16 hard action templates
               0.00 seconds reachability analysis, yielding 395 facts and 561 actions
               0.00 seconds creating final representation with 392 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 158 states, to a max depth of 0
               0.05 seconds total time

