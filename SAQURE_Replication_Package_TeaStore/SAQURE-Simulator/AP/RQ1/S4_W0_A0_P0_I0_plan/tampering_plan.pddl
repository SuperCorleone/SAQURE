
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-TAMPERING' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:    9
                               8
                               7
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
        3: ATTACKER-CREATES-SYMBOLIC-LINK-TO-SENSITIVE-FILE TEASTORE HOST-OS_TEASTORE SYMBOLIC-LINK1 TEMPORARY-DIRECTORY_TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE FILENAME-PATTERN_TEASTORE
        4: USER-TRIGGERS-FILEBACKEDOUTPUTSTREAM-FUNCTIONALITY-WRITES-DATA USER1 TEASTORE SYMBOLIC-LINK1 CVE_2023_2976
        5: APPLICATION-CREATES-TEMP-FILE-RESOLVING-TO-SYMLINK TEASTORE TEMPORARY-FILE_TEASTORE SYMBOLIC-LINK1 SENSITIVE-SYSTEM-FILE_TEASTORE TEMPORARY-DIRECTORY_TEASTORE
        6: APPLICATION-WRITES-DATA-INTO-RESOLVED-SENSITIVE-FILE- TEASTORE TEMPORARY-FILE_TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE USER1-PASSWORD-HASH_TEASTORE
        7: ATTACKER-ACHIEVES-UNAUTHORIZED-TAMPERING TEASTORE SENSITIVE-SYSTEM-FILE_TEASTORE USER1-PASSWORD-HASH_TEASTORE
plan cost: 41.000000

time spent:    0.05 seconds instantiating 6744 easy, 99 hard action templates
               0.00 seconds reachability analysis, yielding 438 facts and 444 actions
               0.00 seconds creating final representation with 434 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.01 seconds searching, evaluating 129 states, to a max depth of 0
               0.06 seconds total time

