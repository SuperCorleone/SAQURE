
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-DENIAL_OF_SERVICE' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:    6
                               4
                               3
                               2
                               1
                               0

ff: found legal plan as follows
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2023-34055 SEFA SPRINGBOOT_SEFA
        1: ATTACKER-CRAFTS-HTTP-FLOOD-SCRIPT SEFA HTTP-FLOOD-SCRIPT1 SPRINGBOOT_SEFA CVE_2023_34055
        2: ATTACKER-INITIATES-HTTP-FLOOD SEFA HTTP-FLOOD-SCRIPT1 SPRINGBOOT_SEFA CVE_2023_34055
        3: APPLICATION-PROCESSES-HTTP-REQUESTS-WITHOUT-LIMITS SPRINGBOOT_SEFA HTTP-FLOOD-SCRIPT1
        4: APPLICATION-EXHAUSTS-SERVER-MEMORY-RESOURCES SEFA SPRINGBOOT_SEFA
plan cost: 47.000000

time spent:    0.05 seconds instantiating 6738 easy, 97 hard action templates
               0.00 seconds reachability analysis, yielding 267 facts and 439 actions
               0.00 seconds creating final representation with 264 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 49 states, to a max depth of 0
               0.05 seconds total time

