
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

Advancing to goal distance:   16
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2024-47072 TEASTORE XSTREAMLIBRARY_TEASTORE BINARY-STREAM-DRIVER_TEASTORE API-ENDPOINT_TEASTORE
        1: ATTACKER-CRAFTS-MALICIOUS-BINARY-XSTREAM-PAYLOAD TEASTORE BINARY-PAYLOAD1 SNAKEYAML-LIBRARY_TEASTORE CVE_2024_47072
        2: ATTACKER-SENDS-HTTP-POST-REQUEST-WITH-BINARY-PAYLOAD TEASTORE HTTP-POST-REQUEST1 BINARY-PAYLOAD1 API-ENDPOINT_TEASTORE CVE_2024_47072
        3: APPLICATION-RECEIVES-HTTP-POST-REQUEST-WITH-MALICIOUS-PAYLOAD TEASTORE HTTP-POST-REQUEST1 BINARY-PAYLOAD1 API-ENDPOINT_TEASTORE
        4: APPLICATION-EXTRACTS-BINARY-PAYLOAD-FROM-HTTP-REQUEST TEASTORE HTTP-POST-REQUEST1 BINARY-PAYLOAD1 API-ENDPOINT_TEASTORE
        5: APPLICATION-USES-XSTREAM-BINARY-DRIVER TEASTORE XSTREAMLIBRARY_TEASTORE BINARY-STREAM-DRIVER_TEASTORE BINARY-PAYLOAD1
        6: APPLICATION-BINARY-DRIVER-ALLOCATES-STACK-FRAMES-FOR-RECURSIVE-DECODING XSTREAMLIBRARY_TEASTORE BINARY-STREAM-DRIVER_TEASTORE BINARY-PAYLOAD1 TEASTORE
        7: APPLICATION-TRIGGERS-STACKOVERFLOW-ERROR TEASTORE CVE_2024_47072
        8: APPLICATION-BECOMES-UNRESPONSIVE TEASTORE
plan cost: 37.000000

time spent:    0.04 seconds instantiating 5266 easy, 102 hard action templates
               0.00 seconds reachability analysis, yielding 428 facts and 837 actions
               0.00 seconds creating final representation with 425 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 149 states, to a max depth of 0
               0.04 seconds total time

