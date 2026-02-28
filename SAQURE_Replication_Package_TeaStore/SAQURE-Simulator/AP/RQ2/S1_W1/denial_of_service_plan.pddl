
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

Advancing to goal distance:   14
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACE-TO-ATTACKERS-CVE-2024-38809 TEASTORE SPRING-FRAMEWORK1 HTTP-ENDPOINT_TEASTORE ETAG-HANDLER_TEASTORE
        1: ATTACKER-CRAFTS-MALICIOUS-HTTP-REQUEST-WITH-PATHOLOGICAL-ETAG TEASTORE USER-HTTP-REQUEST1 ETAG-VALUE_TEASTORE CVE_2024_38809
        2: ATTACKER-OPENS-TCP-CONNECTION TEASTORE USER-HTTP-REQUEST1 TCP-CONNECTION_TEASTORE HTTP-ENDPOINT_TEASTORE
        3: APPLICATION-ACCEPTS-TCP-CONNECTION TEASTORE TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE HTTP-ENDPOINT_TEASTORE
        4: ATTACKER-SENDS-CRAFTED-HTTP-REQUEST-WITH-IF-MATCH-HEADER TEASTORE USER-HTTP-REQUEST1 TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE ETAG-VALUE_TEASTORE
        5: APPLICATION-RECEIVES-HTTP-REQUEST TEASTORE USER-HTTP-REQUEST1 TCP-SERVER_TEASTORE TCP-CONNECTION_TEASTORE
        6: APPLICATION-SERVER-READS-HTTP-REQUEST-BYTES TEASTORE USER-HTTP-REQUEST1 TCP-CONNECTION_TEASTORE
        7: APPLICATION-EXTRACTS-IF-MATCH-HEADER-VALUE TEASTORE USER-HTTP-REQUEST1 ETAG-VALUE_TEASTORE HTTP-ENDPOINT_TEASTORE
        8: APPLICATION-CALLS-VULNERABLE-SPRING-ETAG-PARSING-ROUTINE TEASTORE SPRING-FRAMEWORK1 ETAG-VALUE_TEASTORE ETAG-HANDLER_TEASTORE
        9: APPLICATION-SUFFERS-RESOURCE-EXHAUSTION TEASTORE CVE_2024_38809 SPRING-FRAMEWORK1 ETAG-VALUE_TEASTORE
       10: APPLICATION-BECOMES-UNRESPONSIVE TEASTORE
plan cost: 73.000000

time spent:    0.04 seconds instantiating 5330 easy, 98 hard action templates
               0.00 seconds reachability analysis, yielding 359 facts and 681 actions
               0.00 seconds creating final representation with 356 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 179 states, to a max depth of 0
               0.04 seconds total time

