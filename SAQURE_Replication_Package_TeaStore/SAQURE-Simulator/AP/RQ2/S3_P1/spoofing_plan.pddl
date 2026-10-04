
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-SPOOFING' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:   23
                               9
                               8
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2023-2976 TEASTORE GUAVA-LIBRARY_TEASTORE HOST-OS_TEASTORE
        1: ATTACKER-IDENTIFIES-APPLICATION-DEFAULT-JAVA-TEMP-DIRECTORY TEASTORE CVE_2023_2976 TEMPORARY-DIRECTORY_TEASTORE
        2: ATTACKER-PREDICTS-TEMP-FILE-NAMING-PATTERN TEASTORE FILENAME-PATTERN_TEASTORE CVE_2023_2976 TEMPORARY-DIRECTORY_TEASTORE
        3: ATTACKER-CREATES-SYMBOLIC-LINK-TO-ATTACKER-CONTROLLED-FILE TEASTORE HOST-OS_TEASTORE SYMBOLIC-LINK1 TEMPORARY-DIRECTORY_TEASTORE CONTROLLED-FILE1 FILENAME-PATTERN_TEASTORE
        4: USER-TRIGGERS-FILEBACKEDOUTPUTSTREAM-FUNCTIONALITY-BUFFERS-DATA USER1 TEASTORE CVE_2023_2976
        5: APPLICATION-CREATES-TEMP-FILE-RESOLVING-TO-SYMLINK TEASTORE TEMPORARY-FILE_TEASTORE SYMBOLIC-LINK1 CONTROLLED-FILE1 TEMPORARY-DIRECTORY_TEASTORE
        6: APPLICATION-WRITES-DATA-INTO-RESOLVED-ATTACKER-CONTROLLED-FILE TEASTORE TEMPORARY-FILE_TEASTORE CONTROLLED-FILE1 USER1-PASSWORD_TEASTORE
        7: ATTACKER-RECEIVES-SENSITIVE-INFORMATION TEASTORE USER1-PASSWORD_TEASTORE CVE_2023_2976
        8: ATTACKER-USES-USER-CREDENTIALS-LOGIN-TARGET-APPLICATION USER1 USER1-PASSWORD_TEASTORE TEASTORE
plan cost: 42.000000

time spent:    0.07 seconds instantiating 6763 easy, 98 hard action templates
               0.00 seconds reachability analysis, yielding 358 facts and 358 actions
               0.00 seconds creating final representation with 354 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 139 states, to a max depth of 0
               0.07 seconds total time

