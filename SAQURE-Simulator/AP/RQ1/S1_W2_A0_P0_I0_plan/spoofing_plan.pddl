
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2023-2976 TEASTORE GUAVA-LIBRARY_TEASTORE HOST-OS_TEASTORE
        1: USER-TRIGGERS-FILEBACKEDOUTPUTSTREAM-FUNCTIONALITY-BUFFERS-DATA USER1 TEASTORE CVE_2023_2976
        2: ATTACKER-IDENTIFIES-APPLICATION-DEFAULT-JAVA-TEMP-DIRECTORY TEASTORE CVE_2023_2976 TEMPORARY-DIRECTORY_TEASTORE
        3: APPLICATION-CREATES-TEMP-FILE-WITH-INSECURE-PERMISSIONS TEASTORE TEMPORARY-FILE_TEASTORE TEMPORARY-DIRECTORY_TEASTORE HOST-OS_TEASTORE
        4: ATTACKER-PREDICTS-TEMP-FILE-NAMING-PATTERN TEASTORE FILENAME-PATTERN_TEASTORE CVE_2023_2976 TEMPORARY-DIRECTORY_TEASTORE
        5: ATTACKER-CREATES-SYMBOLIC-LINK-TO-ATTACKER-CONTROLLED-FILE TEASTORE HOST-OS_TEASTORE SYMBOLIC-LINK1 TEMPORARY-DIRECTORY_TEASTORE CONTROLLED-FILE1 FILENAME-PATTERN_TEASTORE
        6: APPLICATION-CREATES-TEMP-FILE-RESOLVING-TO-SYMLINK TEASTORE TEMPORARY-FILE_TEASTORE SYMBOLIC-LINK1 CONTROLLED-FILE1 TEMPORARY-DIRECTORY_TEASTORE
        7: APPLICATION-WRITES-DATA-INTO-RESOLVED-ATTACKER-CONTROLLED-FILE TEASTORE TEMPORARY-FILE_TEASTORE CONTROLLED-FILE1 USER1-PASSWORD_TEASTORE
        8: ATTACKER-RECEIVES-SENSITIVE-INFORMATION TEASTORE USER1-PASSWORD_TEASTORE CVE_2023_2976
        9: ATTACKER-USES-USER-CREDENTIALS-LOGIN-TARGET-APPLICATION USER1 USER1-PASSWORD_TEASTORE TEASTORE
plan cost: 43.000000

time spent:    0.05 seconds instantiating 6762 easy, 104 hard action templates
               0.00 seconds reachability analysis, yielding 561 facts and 693 actions
               0.00 seconds creating final representation with 557 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.01 seconds searching, evaluating 246 states, to a max depth of 0
               0.06 seconds total time

