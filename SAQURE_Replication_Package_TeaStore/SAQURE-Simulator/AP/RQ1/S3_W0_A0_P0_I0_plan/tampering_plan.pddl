
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

Advancing to goal distance:   10
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACE-TO-ATTACKERS-CVE-2023-2976 TEASTORE GUAVA-LIBRARY_TEASTORE HOST-OS_TEASTORE
        1: USER-TRIGGERS-FILEBACKEDOUTPUTSTREAM-FUNCTIONALITY-BUFFERS-DATA USER1 TEASTORE CVE_2023_2976
        2: ATTACKER-IDENTIFIES-APPLICATION-DEFAULT-JAVA-TEMP-DIRECTORY TEASTORE CVE_2023_2976 TEMPORARY-DIRECTORY_TEASTORE
        3: APPLICATION-CREATES-TEMP-FILE-WITH-INSECURE-PERMISSIONS TEASTORE TEMPORARY-FILE_TEASTORE TEMPORARY-DIRECTORY_TEASTORE HOST-OS_TEASTORE
        4: ATTACKER-PREDICTS-TEMP-FILE-NAMING-PATTERN TEASTORE FILENAME-PATTERN_TEASTORE CVE_2023_2976 TEMPORARY-DIRECTORY_TEASTORE
        5: ATTACKER-CREATES-SYMBOLIC-LINK-TO-SENSITIVE-FILE TEASTORE HOST-OS_TEASTORE SYMBOLIC-LINK1 TEMPORARY-DIRECTORY_TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE FILENAME-PATTERN_TEASTORE
        6: USER-TRIGGERS-FILEBACKEDOUTPUTSTREAM-FUNCTIONALITY-WRITES-DATA USER1 TEASTORE SYMBOLIC-LINK1 CVE_2023_2976
        7: APPLICATION-CREATES-TEMP-FILE-RESOLVING-TO-SYMLINK TEASTORE TEMPORARY-FILE_TEASTORE SYMBOLIC-LINK1 SENSITIVE-SYSTEM-FILE_TEASTORE TEMPORARY-DIRECTORY_TEASTORE
        8: APPLICATION-WRITES-DATA-INTO-RESOLVED-SENSITIVE-FILE TEASTORE TEMPORARY-FILE_TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE USER1-PASSWORD_TEASTORE
        9: ATTACKER-ACHIEVES-UNAUTHORIZED-TAMPERING TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE USER1-PASSWORD_TEASTORE
plan cost: 43.000000

time spent:    0.07 seconds instantiating 4854 easy, 16 hard action templates
               0.00 seconds reachability analysis, yielding 469 facts and 445 actions
               0.00 seconds creating final representation with 465 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 192 states, to a max depth of 0
               0.07 seconds total time

