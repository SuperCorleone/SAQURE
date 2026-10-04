
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
                               6
                               5
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2023-2976 SEFA GUAVA-LIBRARY_SEFA HOST-OS_SEFA
        1: ATTACKER-IDENTIFIES-APPLICATION-DEFAULT-JAVA-TEMP-DIRECTORY SEFA CVE_2023_2976 TEMPORARY-DIRECTORY_SEFA
        2: ATTACKER-PREDICTS-TEMP-FILE-NAMING-PATTERN SEFA FILENAME-PATTERN_SEFA CVE_2023_2976 TEMPORARY-DIRECTORY_SEFA
        3: ATTACKER-CREATES-SYMBOLIC-LINK-TO-ATTACKER-CONTROLLED-FILE SEFA HOST-OS_SEFA SYMBOLIC-LINK1 TEMPORARY-DIRECTORY_SEFA CONTROLLED-FILE1 FILENAME-PATTERN_SEFA
        4: USER-TRIGGERS-FILEBACKEDOUTPUTSTREAM-FUNCTIONALITY-BUFFERS-DATA USER1 SEFA CVE_2023_2976
        5: APPLICATION-CREATES-TEMP-FILE-RESOLVING-TO-SYMLINK SEFA TEMPORARY-FILE_SEFA SYMBOLIC-LINK1 CONTROLLED-FILE1 TEMPORARY-DIRECTORY_SEFA
        6: APPLICATION-WRITES-DATA-INTO-RESOLVED-ATTACKER-CONTROLLED-FILE SEFA TEMPORARY-FILE_SEFA CONTROLLED-FILE1 USER1-PASSWORD_SEFA
        7: ATTACKER-RECEIVES-SENSITIVE-INFORMATION SEFA USER1-PASSWORD_SEFA CVE_2023_2976
        8: ATTACKER-USES-USER-CREDENTIALS-LOGIN-TARGET-APPLICATION USER1 USER1-PASSWORD_SEFA SEFA
plan cost: 42.000000

time spent:    0.06 seconds instantiating 6751 easy, 96 hard action templates
               0.01 seconds reachability analysis, yielding 210 facts and 137 actions
               0.00 seconds creating final representation with 206 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 112 states, to a max depth of 0
               0.07 seconds total time

