
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

Advancing to goal distance:   14
                              13
                              12
                              11
                              10
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
step    0: APPLICATION-EXPOSES-ATTACK-SURFACES-TO-ATTACKERS-CVE-2022-1471 SEFA SNAKEYAML-LIBRARY_SEFA JAVA_SEFA YAML-ENDPOINT_SEFA
        1: ATTACKER-CRAFTS-MALICIOUS-JAVA-CLASS SEFA MALICIOUS-JAVA-CLASS1 COMMAND-EXECUTION-LOGIC1 CVE_2022_1471
        2: ATTACKER-HOSTS-MALICIOUS-CLASS-ON-SERVER SEFA MALICIOUS-JAVA-CLASS1 MALICIOUS-SERVER1 CVE_2022_1471
        3: ATTACKER-SETS-UP-MALICIOUS-LDAP-RMI-REGISTRY SEFA MALICIOUS-SERVER1 LDAP-SERVICE1 RMI-SERVICE1 MALICIOUS-JAVA-CLASS1 CVE_2022_1471
        4: ATTACKER-GENERATES-JNDI-ENDPOINT-WITH-LDAP-OR-RMI SEFA JNDI-ENDPOINT1 MALICIOUS-JAVA-CLASS1 LDAP-SERVICE1 RMI-SERVICE1 CVE_2022_1471
        5: ATTACKER-CRAFTS-MALICIOUS-YAML-PAYLOAD SEFA YAML-PAYLOAD1 JAVA-GADGET-CLASS_SEFA JNDI-ENDPOINT1 MALICIOUS-JAVA-CLASS1 CVE_2022_1471
        6: ATTACKER-SENDS-MALICIOUS-YAML-VIA-HTTP-POST HTTP-POST-REQUEST1 SEFA YAML-PAYLOAD1 YAML-ENDPOINT_SEFA CVE_2022_1471
        7: APPLICATION-RECEIVES-HTTP-POST-REQUEST-WITH-MALICIOUS-PAYLOAD SEFA HTTP-POST-REQUEST1 YAML-PAYLOAD1 YAML-ENDPOINT_SEFA
        8: APPLICATION-PASSES-YAML-TO-SNAKEYAML-LOADER HTTP-POST-REQUEST1 YAML-PAYLOAD1 SEFA SNAKEYAML-LIBRARY_SEFA
        9: APPLICATION-STARTS-YAML-DESERIALIZATION-WITH-CONSTRUCTOR YAML-PAYLOAD1 SNAKEYAML-LIBRARY_SEFA YAML-CONSTRUCTOR_SEFA SEFA
       10: APPLICATION-INSTANTIATES-DANGEROUS-JAVA-GADGET-CLASS SEFA YAML-CONSTRUCTOR_SEFA JAVA-GADGET-CLASS_SEFA YAML-PAYLOAD1
       11: APPLICATION-LOADS-MALICIOUS-CLASS-FROM-JNDI-ENDPOINT SEFA JAVA-GADGET-CLASS_SEFA JNDI-ENDPOINT1 MALICIOUS-JAVA-CLASS1 YAML-PAYLOAD1 CVE_2022_1471
       12: APPLICATION-INSTANTIATES-MALICIOUS-ATTACKER-CLASS SEFA YAML-CONSTRUCTOR_SEFA MALICIOUS-JAVA-CLASS1 CVE_2022_1471
       13: APPLICATION-EXECUTES-ATTACKER-COMMAND-WITH-PRIVILEGES SEFA MALICIOUS-JAVA-CLASS1 COMMAND-EXECUTION-LOGIC1 CVE_2022_1471
plan cost: 15.000000

time spent:    0.04 seconds instantiating 5203 easy, 102 hard action templates
               0.00 seconds reachability analysis, yielding 427 facts and 892 actions
               0.00 seconds creating final representation with 424 relevant facts, 1 relevant fluents
               0.00 seconds computing LNF
               0.00 seconds building connectivity graph
               0.00 seconds searching, evaluating 230 states, to a max depth of 0
               0.04 seconds total time

