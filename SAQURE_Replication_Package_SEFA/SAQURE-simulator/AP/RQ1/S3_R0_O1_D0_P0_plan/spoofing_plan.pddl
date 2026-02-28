
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2025-22228 SEFA SPRING-SECURITY_SEFA PASSWORD_ENCODER_SEFA
        1: USER-SETS-WEAK-PASSWORD-LONGER-THAN-72-CHARS USER1 SEFA USER1-PASSWORD-HASH_SEFA
        2: APPLICATION-HASHES-AND-STORES-FIRST-72-CHARS-ONLY USER1 SEFA USER1-PASSWORD-HASH_SEFA USER1-PASSWORD-HASH_SEFA PASSWORD_ENCODER_SEFA
        3: ATTACKER-CRAFTS-ONLINE-BRUTE-FORCE-SCRIPT ONLINE-BRUTE-FORCE-SCRIPT1 SEFA USER1-PASSWORD-HASH_SEFA CVE_2025_22228
        4: ATTACKER-SENDS-LARGE-AMOUNT-AUTOMATED-LOGIN-REQUESTS-VIA-SCRIPT ONLINE-BRUTE-FORCE-SCRIPT1 SEFA LOGIN-REQUEST1_SEFA USER1-PASSWORD-HASH_SEFA
        5: APPLICATION-RECEIVES-LOGIN-REQUESTS SEFA LOGIN-REQUEST1_SEFA USER1-PASSWORD-HASH_SEFA
        6: APPLICATION-TRUNCATES-INPUT-PASSWORD-TO-72-CHARS SEFA LOGIN-REQUEST1_SEFA PASSWORD_ENCODER_SEFA USER1-PASSWORD-HASH_SEFA
        7: APPLICATION-HASHES-TRUNCATED-72-CHARS-INPUT SEFA USER1-PASSWORD-HASH_SEFA PASSWORD_ENCODER_SEFA
        8: APPLICATION-COMPARES-HASHES-WITH-STORED-HASH SEFA USER1-PASSWORD-HASH_SEFA USER1-PASSWORD-HASH_SEFA
        9: APPLICATION-AUTHENTICATES-ATTACKER-SUCCESSFULLY SEFA USER1-PASSWORD-HASH_SEFA USER1-PASSWORD-HASH_SEFA CVE_2025_22228
plan cost: 146.000000

time spent:    0.04 seconds instantiating 5430 easy, 105 hard action templates
               0.00 seconds reachability analysis, yielding 500 facts and 1173 actions
               0.00 seconds creating final representation with 497 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.01 seconds building connectivity graph
               0.01 seconds searching, evaluating 188 states, to a max depth of 0
               0.06 seconds total time

