
ff: parsing domain file
domain 'AED' defined
 ... done.
ff: parsing problem file
problem 'AEDI-INFORMATION_DISCLOSURE' defined
 ... done.


translating negated cond for predicate SCRIPT-EXECUTION-PROMPT-ENABLED

ff: search configuration is A*epsilon with weight 1.
Metric is ((1.00*[RF0](TOTAL-COST)) - () + 0.00)
COST MINIMIZATION DONE (WITH cost-minimizing relaxed plans).

Advancing to goal distance:   13
                              11
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2024-38816 SEFA SPRING-FRAMEWORK1 ROUTER-FUNCTION_SEFA RESOURCE-HANDLER_SEFA FILESYSTEM-RESOURCE_SEFA CVE_2023_46589
        1: ATTACKER-CRAFTS-MALICIOUS-PATH-TRAVERSAL-URL PATH-TRAVERSAL-URL1 PATH-TRAVERSAL-PAYLOAD1 SENSITIVE-FILE1_SEFA SEFA CVE_2024_38816
        2: ATTACKER-CLICKS-MALICIOUS-URL-INCLUDES-PATH-TRAVERSAL-PYLOAD BROWSER-CHROME PATH-TRAVERSAL-URL1
        3: ATTACKER-BROWSER-SENDS-MALICIOUS-HTTP-GET-REQUEST-WITH-PATH-TRAVERSAL-PAYLOAD BROWSER-CHROME HTTP-GET-REQUEST1 PATH-TRAVERSAL-URL1 PATH-TRAVERSAL-PAYLOAD1
        4: APPLICATION-RECEIVES-HTTP-GET-REQUEST HTTP-GET-REQUEST1 SEFA
        5: APPLICATION-MATCHES-REQUEST-TO-RESOURCE-HANDLER HTTP-GET-REQUEST1 PATH-TRAVERSAL-URL1 PATH-TRAVERSAL-PAYLOAD1 SEFA ROUTER-FUNCTION_SEFA RESOURCE-HANDLER_SEFA CVE_2024_38816
        6: APPLICATION-ROUTES-REQUEST-TO-RESOURCE-HANDLER PATH-TRAVERSAL-URL1 RESOURCE-HANDLER_SEFA ROUTER-FUNCTION_SEFA
        7: APPLICATION-RESOURCE-HANDLER-CONCATENATES-PATH-WITHOUT-NORMALIZATION PATH-TRAVERSAL-URL1 RESOURCE-HANDLER_SEFA PATH-TRAVERSAL-PAYLOAD1 FILESYSTEM-PATH_SEFA SEFA
        8: APPLICATION-READS-CONTENT-FROM-CONCATENATED-PATH FILESYSTEM-PATH_SEFA PATH-TRAVERSAL-PAYLOAD1 SENSITIVE-FILE1_SEFA SENSITIVE-FILE-CONTENT1 SEFA
        9: APPLICATION-SERVER-RETURNS-SENSITIVE-INFORMATION HTTP-GET-REQUEST1 SENSITIVE-FILE-CONTENT1 SEFA
       10: ATTACKER-RECEIVES-SENSITIVE-INFORMATION SEFA SENSITIVE-FILE-CONTENT1 CVE_2024_38816
plan cost: 39.000000

time spent:    0.08 seconds instantiating 6749 easy, 95 hard action templates
               0.00 seconds reachability analysis, yielding 137 facts and 189 actions
               0.00 seconds creating final representation with 133 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 143 states, to a max depth of 0
               0.08 seconds total time

