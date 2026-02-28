
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2025-22228 TEASTORE SPRING-SECURITY_TEASTORE PASSWORD_ENCODER_TEASTORE
        1: USER-SETS-WEAK-PASSWORD-LONGER-THAN-72-CHARS USER1 TEASTORE USER1-PASSWORD-HASH_TEASTORE
        2: APPLICATION-HASHES-AND-STORES-FIRST-72-CHARS-ONLY USER1 TEASTORE USER1-PASSWORD-HASH_TEASTORE USER1-PASSWORD-HASH_TEASTORE PASSWORD_ENCODER_TEASTORE
        3: ATTACKER-CRAFTS-ONLINE-BRUTE-FORCE-SCRIPT ONLINE-BRUTE-FORCE-SCRIPT1 TEASTORE USER1-PASSWORD-HASH_TEASTORE CVE_2025_22228
        4: ATTACKER-SENDS-LARGE-AMOUNT-AUTOMATED-LOGIN-REQUESTS-VIA-SCRIPT ONLINE-BRUTE-FORCE-SCRIPT1 TEASTORE LOGIN-REQUEST1_TEASTORE USER1-PASSWORD-HASH_TEASTORE
        5: APPLICATION-RECEIVES-LOGIN-REQUESTS TEASTORE LOGIN-REQUEST1_TEASTORE USER1-PASSWORD-HASH_TEASTORE
        6: APPLICATION-TRUNCATES-INPUT-PASSWORD-TO-72-CHARS TEASTORE LOGIN-REQUEST1_TEASTORE PASSWORD_ENCODER_TEASTORE USER1-PASSWORD-HASH_TEASTORE
        7: APPLICATION-HASHES-TRUNCATED-72-CHARS-INPUT TEASTORE USER1-PASSWORD-HASH_TEASTORE PASSWORD_ENCODER_TEASTORE
        8: APPLICATION-COMPARES-HASHES-WITH-STORED-HASH TEASTORE USER1-PASSWORD-HASH_TEASTORE USER1-PASSWORD-HASH_TEASTORE
        9: APPLICATION-AUTHENTICATES-ATTACKER-SUCCESSFULLY TEASTORE USER1-PASSWORD-HASH_TEASTORE USER1-PASSWORD-HASH_TEASTORE CVE_2025_22228
plan cost: 39.000000

time spent:    0.04 seconds instantiating 4391 easy, 15 hard action templates
               0.01 seconds reachability analysis, yielding 348 facts and 485 actions
               0.00 seconds creating final representation with 345 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 108 states, to a max depth of 0
               0.05 seconds total time

