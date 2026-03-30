
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

Advancing to goal distance:   14
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2024-38820 TEASTORE SPRING-FRAMEWORK1 LOCALE-CONFIG_TEASTORE DATABINDER_TEASTORE WEB-CONTROLLER_TEASTORE ADMIN-FIELD-PATTERN
        1: ATTACKER-REGISTERS-ACCOUNT-ON-TARGET-APPLICATION ATTACKER-ACCOUNT_TEASTORE TEASTORE ATTACKER-SESSION_TEASTORE CVE_2024_38820
        2: ATTACKER-CRAFTS-MALICIOUS-URL-WITH-LOCALE-BYPASS CRAFTED-LOCALE-BYPASS-URL1 TEASTORE TURKISH-I-PARAM ATTACKER-ACCOUNT_TEASTORE CVE_2024_38820
        3: ATTACKER-CLICKS-MALICIOUS-URL-INCLUDES-LOCALE-BYPASS-PYLOAD BROWSER-CHROME CRAFTED-LOCALE-BYPASS-URL1 TURKISH-I-PARAM
        4: ATTACKER-BROWSER-SENDS-MALICIOUS-HTTP-GET-REQUEST-WITH-LOCALE-BYPASS-PYLOAD HTTP-GET-REQUEST1 CRAFTED-LOCALE-BYPASS-URL1 BROWSER-CHROME TURKISH-I-PARAM
        5: APPLICATION-RECEIVES-HTTP-GET-REQUEST HTTP-GET-REQUEST1 TEASTORE
        6: APPLICATION-SERVER-INVOKES-DATABINDER-WITH-LOCALE-TRANSFORMATION TEASTORE HTTP-GET-REQUEST1 CRAFTED-LOCALE-BYPASS-URL1 TURKISH-I-PARAM DATABINDER_TEASTORE TRANSFORMED-PARAM1 CVE_2024_38820
        7: APPLICATION-DATABINDER-FAILS-TO-MATCH-DISALLOWED-FIELDS-PATTERN TEASTORE DATABINDER_TEASTORE TURKISH-I-PARAM TRANSFORMED-PARAM1 ADMIN-FIELD-PATTERN
        8: APPLICATION-SERVER-SETS-ADMIN-FIELD-FOR-ATTACKER TEASTORE ATTACKER-ACCOUNT_TEASTORE TRANSFORMED-PARAM1
plan cost: 71.000000

time spent:    0.06 seconds instantiating 6769 easy, 98 hard action templates
               0.00 seconds reachability analysis, yielding 268 facts and 321 actions
               0.00 seconds creating final representation with 264 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 110 states, to a max depth of 0
               0.06 seconds total time

