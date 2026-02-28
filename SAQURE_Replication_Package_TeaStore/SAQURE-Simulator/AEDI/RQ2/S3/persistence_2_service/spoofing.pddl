(define (problem elevate-privilege-problem)
  (:domain attack-path-planner)
  
  (:objects
    CVE_2023_2976 - cve-identifier
    attacker1 - attacker
    
    ;;;(1).=================================Application Configuration====================;;;
    ;;; Entity declaration ;;;
    
    TeaStore - application ;application
    logback_TeaStore - logback
    janino-library_TeaStore - java-library
    legit-logback-config - logback-config
    malicious-logback-config - logback-config
    config-dir_TeaStore - path
    gmail - comchannel
    browser-chrome - browser
    browser-IE - browser
    email-site - site
    logback-env-var1 - env-var


   ;; === Added for CVE-2024-38286==
    tomcat_TeaStore - tomcat
    tls-connector_TeaStore - tls-connector

   ;; ==== Added for CVE-2024-38820 ====;;
   databinder_TeaStore - data-binder
   ;; Locale Configuration
   locale-config_TeaStore - locale-config
   ;; Security Patterns
   admin-field-pattern - disallowed-pattern
  
  ;; ==== Added for CVE-2022-1471 =====
  snakeyaml-library_TeaStore - snakeyaml-library
  java_TeaStore - software
  yaml-endpoint_TeaStore - yaml-endpoint
  java-gadget-class_TeaStore - java-gadget-class
  yaml-constructor_TeaStore - yaml-constructor


    ;;;(2).================================USER================================;;;
    user1 - user


   ;;;(3).=============================Attacker Capability==========================;;;
   malicious-msg - message
   malicious-logback-config - logback-config
   ;;==== Added for CVE-2024-12798 AP 1.2 =====
   malicious-server1 - controlled-server
   malicious-file-url1 - file-url
   ;;==== Added for CVE-2024-12798 AP 1.3 =====
   malicious-forged-website1 - website
   forged-website1-url - website-url
   ;;==== Added for CVE-2024-12798 AP 2.1 =====
   malicious-logback-env-var-set-script1 - script
   ;; ==== Added for CVE-2024-12798 AP 2.2 ===
   script-url1 - script-url
   ;; === Added for CVE-2024-38286==
   tomcat-tls-flood-script1 - script
    ; ==== Added for AP 2 =====
   tomcat-tls-initial-handshake-request-script1 - script 
   tomcat-tls-renegotiation-script1 -script
   ;; ==== Added for CVE-2024-22243 ====;;
   phishing-url1 - phishing-url     ;https://evil.com
   redirect-url1 - redirect-url     ;https://teastore.com/redirect?url=https://teastore.com:80@evil.com
   valiation-pass-pyload1 - payload-string      ;https://teastore.com:80@evil.com
   ;user1-password_TeaStore - credential
   user1-password_TeaStore - password
   UriComponentsBuilder - url-parser
   url-setting-endpoint1  - endpoint
   Twitter Facebook - social-media
   internal-resource-address1 - internal-address ;http://localhost:8080/internal-data
   sensitive-file-name1 - sensitive-information
   
   ;; ==== Added for CVE-2024-38820 ====;;
   spring-framework1 - spring-framework
   web-controller_TeaStore - web-controller
   attacker-account_TeaStore - account
   attacker-credentials_TeaStore - credential
   attacker-session_TeaStore - session-cookie

   crafted-locale-bypass-url1 - locale-bypass-url
   turkish-i-param - locale-bypass-parameter  ; İsAdmin=true parameter
   transformed-param1 - transformed-parameter  ; i̇sadmin result

   i̇sadmin - parameter-name

  ;; ==== Added for CVE-2023-34055 ====;;
   springboot_TeaStore - spring-boot
   http-flood-script1 - script

  ;; ==== Added for CVE-2024-34447 ====;;
  bouncy-castle-lib_TeaStore - bouncy-castle
  bcjsse-component_TeaStore - bcjsse
  vulnerable-dns-server1 - dns-server
  legit-server1_TeaStore - legitimate-server
  legit-server-address1 - legitimate-ip-address
  malicious-server-address1 - malicious-ip-address
  attacker-domain1 - controlled-domain
  attacker-cert1 - ssl-certificate
  socket_TeaStore - ssl-socket
  TeaStore-microservice - legitimate-service
  
 ;; ==== Added for CVE-2022-40150 ====;;
  jettison-library_TeaStore - java-library
  malicious-jettison-payload1 - json-payload
  API-endpoint_TeaStore - api-endpoint
  http-post-request1 - http-post-request
  SOAP-endpoint_TeaStore - soap-endpoint
  malicious-xml-payload1 - xml-payload


;; ==== Added for CVE-2023-6378====;;
  logbacklib_TeaStore - java-library
  logback-receiver_TeaStore - logback-receiver
  tcp-endpoint_TeaStore - tcp-endpoint
  serialized-payload1 - serialized-payload
  tcp-connection_TeaStore - tcp-connection
  tcp-server_TeaStore - tcp-server

;; ==== Added for CVE-2023-44487====;;
  http2-server_TeaStore - http2-server
  http2-library_TeaStore - http2-library
  http2-connection_TeaStore - http2-connection
  tls-endpoint_TeaStore - tls-endpoint
  tls-connection_TeaStore - tls-connection
  network-interface_TeaStore - network-interface
  http2-settings-frame1 - http2-settings-frame
  http2-settings-ack-frame1 - http2-settings-ack-frame
  rst-stream-frame1 - rst-stream-frame
  stream-limit_TeaStore - stream-limit
  stream-batch1 - stream-batch
  server-resource_TeaStore - server-resource 

;; ==== Added for CVE-2025-22228====;;
  spring-security_TeaStore - spring-security
  password_encoder_TeaStore - password-encoder
  online-brute-force-script1 - script
  user1-password-hash_TeaStore - password-hash
  login-request1_TeaStore - login-request 
  password-encoder_TeaStore - password-encoder

;; ==== Added for CVE_2024_38816====;;
  router-function_TeaStore - router-function
  resource-handler_TeaStore - resource-handler
  filesystem-resource_TeaStore - filesystem-resource
  path-traversal-url1 - path-traversal-url
  path-traversal-payload1 - path-traversal-payload 
  sensitive-file1_TeaStore - sensitive-file
  filesystem-path_TeaStore - filesystem-path
  sensitive-file-content1 - sensitive-information


;; ==== Added for CVE-2022-1471 =====
  command-execution-logic1 - command-execution-logic
  rmi-service1 - rmi-service 
  ldap-service1 - ldap-service
  yaml-payload1 -  yaml-payload
  malicious-java-class1 - java-class
  jndi-endpoint1 - jndi-endpoint

;; ==== Added for CVE-2025-24813 =====
  default-servlet_TeaStore - default-servlet
  public-directory_TeaStore - public-directory
  sensitive-directory_TeaStore - sensitive-directory
  sensitive-file2_TeaStore - sensitive-file
  sensitive-file-content2 - sensitive-information
  http-get-request1 - http-get-request
  http-put-request1 - http-put-request
  malicious-content1 - malicious-content
  content-range-headers1 - content-range-headers
  file-extension1 - file-extension
  jsp-engine_TeaStore - jsp-engine
  web-shell-script1 - web-shell-script
  tomcat-process_TeaStore - tomcat-process

;; ====== added for CVE-2023-2976 ======
  guava-library_TeaStore - java-library
  temporary-directory_TeaStore - temporary-directory
  host-os_TeaStore - host-os
  filename-pattern_TeaStore - filename-pattern
  sensitive-system-file_TeaStore - sensitive-system-file
  temporary-file_TeaStore - temporary-file
  symbolic-link1 - symbolic-link
  controlled-file1 - controlled-file

;; ====== added for CVE-2024-38809 ======
  http-endpoint_TeaStore - http-endpoint
  etag-handler_TeaStore - etag-handler
  etag-value_TeaStore - etag-value

;; ====== added for CVE-2024-47072 ======
  XStreamLibrary_TeaStore - java-library
  binary-stream-driver_TeaStore - binary-stream-driver
  binary-payload1 - binary-payload 

;; ====== added for CVE-2023-33202 ======
  BCLibrary_TeaStore - java-library
  pem-endpoint_TeaStore - pem-endpoint 
  pem-payload1 - pem-payload
  asn1-structure_TeaStore - asn1-structure
  pem-file1 - pem-file


;; ====== added for CVE-2023-46589 ======
  reverse-proxy_TeaStore - reverse-proxy
  trailer-header1 - trailer-header 
  user-session1 - user-session
  sensitive-order1 -  sensitive-information
  user-http-request1 - http-request
  http-response_TeaStore - http-response
  cacheresource1 - cached-resource
  cache-poison-payload1 - cache-poison-payload
  cache1_TeaStore - application-cache
  smuggling-trigger-request1 - http-request
  smuggling-request-cache-poisoning1 - http-request
  smuggling-request-hijack1 - http-request

  
  )

  (:init
    

    (= (total-cost) 0)


   
    ;;;(1).=================================Application Configuration====================;;;
    ;; === for CVE-20224-12798 ===
    ;; entry points: system state
    (has-logback TeaStore logback_TeaStore)
     
    (= (version logback_TeaStore) 1004000002)

    (janino-evaluator-enabled TeaStore logback_TeaStore)
   
    (has-library TeaStore janino-library_TeaStore)
    (janino-library janino-library_TeaStore )
     
    (dynamic-config-loading-enabled TeaStore logback_TeaStore)
    

    (has-config-dir TeaStore config-dir_TeaStore)
    (has-access user1 config-dir_TeaStore)
    (has-write-access user1 config-dir_TeaStore)


    ;not (has-code-execution-restriction TeaStore logback_TeaStore)
    (legitimate-file legit-logback-config) 
    (located-at legit-logback-config config-dir_TeaStore)
    ;not (has-integrity-check TeaStore logback_TeaStore legit-logback-config)
    ;not (has-signature-verification TeaStore logback_TeaStore legit-logback-config)
    (has-controllable-env-vars TeaStore)
     
    (script-execution-prompt-enabled TeaStore)  ;; one key for controlling branches

   ;; ==== Added for CVE-2024-38286 AP 1&2 =====
    (has-tomcat TeaStore tomcat_TeaStore)
    (tomcat-has-tls-connector TeaStore tomcat_TeaStore tls-connector_TeaStore)
    (= (version tomcat_TeaStore) 11000000001)
    (tomcat-tls-renegotiation-enabled TeaStore tomcat_TeaStore tls-connector_TeaStore)
    (has-memory-limitation  TeaStore tomcat_TeaStore)
    ;not (has-memory-protection-mechanisms TeaStore)
    ;not (max-connection-restriction TeaStore)
    ;not (firewall-connection-restriction TeaStore)
    ;not (IDS-monitoring TeaStore)
    ;not (IPS-monitoring TeaStore)
    ;not (WAF-monitoring TeaStore) 

    ;; ==== Added for CVE_2024_22243 AP 1&2 =====
    (has-dependency-on-spring-framework TeaStore)
    (=(version spring-framework1) 6001000001)
    (has-dependency-on-vulnerable-paser TeaStore  UriComponentsBuilder)
    (has-external-settingable-endpoint TeaStore url-setting-endpoint1)
    (url-redirect-enabled TeaStore)
    ;not (url-endpoint-setting-restriction TeaStore url-setting-endpoint1)
     ;(url-endpoint-protocol-restriction TeaStore url-setting-endpoint1)
     ;(url-endpoint-path-restriction TeaStore url-setting-endpoint1)
     ;(url-endpoint-points-restriction TeaStore url-setting-endpoint1)

    (external-resource-accessable TeaStore)
    (internal-resource-accessable TeaStore)
    (vulnerable-host-validation TeaStore)
    ;(depend-blacklist-host-validation TeaStore)
    ;(canonicalization-parse-url TeaStore)
    
    ;not (anti-redirect-protection TeaStore)

    ;not (WAF-malicious-request-bloack TeaStore)
    ;not (IPS-malicious-request-bloack TeaStore)
     
    (data-saved-in-internal-address sensitive-file-name1 internal-resource-address1)


  ;; ==== Added for CVE_2024_38820 AP 1&2 =====
   (has-vulnerable-databinder TeaStore databinder_TeaStore)
   (databinder-parameter-binding-enabled TeaStore databinder_TeaStore)

   (has-disallowed-databinder-fields-configuration TeaStore)

   (databinder-has-write-access-to-properties TeaStore databinder_TeaStore)
   ;not (databinder-has-additional-input-validation-layer TeaStore databinder_TeaStore)      
   (databinder-relies-on-case-insensitive-field-matching TeaStore databinder_TeaStore)
      

   (has-locale-configuration TeaStore locale-config_TeaStore)
   (processes-requests-in-locale-context TeaStore)
   (has-locale-specific-exceptions TeaStore)
   (locale-has-special-case-conversion TeaStore)
   (has-vulnerable-locale-transformation TeaStore)
   
   (locale-dependent-string-processing TeaStore)
   ;not (explicit-locale-specification-in-lowercase TeaStore)

   (has-web-controller-accept-http-post-user-input TeaStore web-controller_TeaStore)
   (accepts-user-controlled-parameter-names TeaStore)

   ;not (has-additional-field-access-controls TeaStore)
   ;not (has-parameter-name-sanitization TeaStore)
   ;not (has-WAF-case-manipulation-rules TeaStore)
   ;not (has-input-filter-case-bypass-detection TeaStore)

   ;; ==== Added for CVE_2023_34055 AP 1&2 =====
   ;1. Application runs vulnerable Spring Boot versions (2.7.0-2.7.17, 3.0.0-3.0.12, or 3.1.0-3.1.5)
  (has-spring-boot TeaStore springboot_TeaStore)
   (= (version springboot_TeaStore) 2007010001) 

  ;2. Application uses Spring MVC or Spring WebFlux web framework
  ;(or (spring-boot-has-mvc TeaStore springboot_TeaStore)
     (spring-boot-has-webflux TeaStore springboot_TeaStore)
  ;   )
  
   ;3. org.springframework.boot:spring-boot-actuator dependency is present on the classpath
  (has-actuator-dependency TeaStore springboot_TeaStore)

  ;4. Web metrics collection is enabled (management.metrics.enable.http.server.requests=true by default)
  (web-metrics-enabled TeaStore springboot_TeaStore)

  ;5. Application accepts and processes HTTP requests from external sources
  (accepts-external-http-requests TeaStore)

  ;6. No rate limiting or request throttling mechanisms are implemented
  ;no (max-connection-restriction TeaStore)

  ;7. Application endpoints are accessible to attackers (no network-level filtering)
  (actuator-endpoints-accessible TeaStore)
  ;no (firewall-connection-restriction TeaStore) 
  
  ;8. Web observations and metrics gathering functionality is activ
  (web-observations-active TeaStore springboot_TeaStore)


   ;9. No monitoring or alerting systems detect unusual request patterns
  ;no (IDS-monitoring TeaStore) 
  ;no (IPS-monitoring TeaStore) 
  ;no (WAF-monitoring TeaStore)

  ;10. Application lacks resource consumption controls or request size limits
  ;no (resource-consumption-controls TeaStore) 
  ;no (request-size-limits TeaStore) 


  ;; ==== Added for CVE_2023_34055 AP 1&2 =====
  ;; Application and Bouncy Castle setup
    (has-bouncy-castle TeaStore bouncy-castle-lib_TeaStore)
    (bcjsse-enabled TeaStore bouncy-castle-lib_TeaStore bcjsse-component_TeaStore)
    (endpoint-identification-enabled TeaStore bcjsse-component_TeaStore)
    (ssl-socket-without-explicit-hostname TeaStore)
    (https-connections-trigger-dns-resolution TeaStore)
    (dns-traffic-interception-allowed TeaStore)
    
    ;; Bouncy Castle version (before 1.78 - vulnerable)
    (= (version bouncy-castle-lib_TeaStore) 1077000000) ; version 1.77
    
    ;; Absence of security measures (using NOT in preconditions)
    ; Note: These are checked as (not ...) in preconditions
    ; (not (additional-certificate-validation TeaStore))
    
    ;; Legitimate server setup
    (legitimate-server-ip-address legit-server1_TeaStore legit-server-address1)

    ;; DNS Server vulnerabilities
    (dns-predictable-source-ports vulnerable-dns-server1)
    (outdated-dns-software vulnerable-dns-server1)
    (dns-attacker-network-reach vulnerable-dns-server1)
    (dns-insufficient-rate-limiting vulnerable-dns-server1)
    (dns-predictable-transaction-ids vulnerable-dns-server1)
    ;; Absence of security measures (using NOT in preconditions)
    ; Note: These are checked as (not ...) in preconditions
    ; (not (dnssec-enabledvulnerable-dns-server1))
    ; (not (doh-enabled vulnerable-dns-server1))
    ; (not (dot-enabled vulnerable-dns-server1))

     ;; ==== Added for CVE_2022_40150 AP 1&2 =====
      
      (has-library TeaStore jettison-library_TeaStore)
      (jettison-library jettison-library_TeaStore)
      (= (version jettison-library_TeaStore) 1005001000)
      (has-api-endpoint TeaStore API-endpoint_TeaStore)
      (has-receive-endpoint TeaStore API-endpoint_TeaStore)
      (accepts-json-input TeaStore API-endpoint_TeaStore)

      ;not (api-endpoint-has-input-validation TeaStore API-endpoint_TeaStore)
      ;not (api-endpoint-has-input-size-limits TeaStore API-endpoint_TeaStore)
      ;not (api-endpoint-has-complexity-limits TeaStore API-endpoint_TeaStore)
      ;not (api-endpoint-has-input-sanitization TeaStore API-endpoint_TeaStore)
      ;not (api-endpoint-has-preprocessing-detection TeaStore API-endpoint_TeaStore)
      ;not (has-heap-memory-consumption-limits TeaStore)
      ;not (has-heap-memory-monitoring TeaStore)
      ;not (has-memory-consumption-limits TeaStore)
      ;not (has-memory-monitoring TeaStore)
      ;not (has-heap-memory-isolation TeaStore)
      ;not (has-heap-memory-quotas TeaStore)
      ;not (has-rate-limiting TeaStore API-endpoint_TeaStore)
      ;not (has-throttling-mechanisms TeaStore API-endpoint_TeaStore)
      ;not (has-waf-protection TeaStore)
      ;not (has-waf-json-payload-detection TeaStore)
    
      ;;==== for AP 2===
      (has-receive-endpoint TeaStore SOAP-endpoint_TeaStore)
      (has-soap-endpoint TeaStore SOAP-endpoint_TeaStore)

      ;; ==== Added for CVE_2022_40149 AP 1&2 =====
      ;not (has-stack-memory-consumption-limits TeaStore )
      ;not (has-stack-memory-monitoring TeaStore)
      ;not (has-stack-memory-isolation TeaStore)
      ;not (has-stack-memory-quotas TeaStore)

      ;; ==== Added for CVE-2023-6378 =====
      (has-library TeaStore logbacklib_TeaStore)
      (logback-library logbacklib_TeaStore)
      (= (version logbacklib_TeaStore) 1004011000) 
      (has-receiver-component TeaStore logback-receiver_TeaStore)
      (logback-receiver-deployed logback-receiver_TeaStore)
      (logback-receiver-configured logback-receiver_TeaStore)
      (logback-receiver-has-tcp-endpoint TeaStore  tcp-endpoint_TeaStore)
      (logback-receiver-listens-on-port logback-receiver_TeaStore  tcp-endpoint_TeaStore)
      (tcp-endpoint-external-access-allowed  tcp-endpoint_TeaStore)
      (tcp-endpoint-firewall-permits-inbound  tcp-endpoint_TeaStore)
      ;not (has-deserialization-validation TeaStore)
      ;not (has-input-sanitization TeaStore)
      ;not (has-deserialization-filtering TeaStore)
      ;not (logback-receiver-requires-authentication logback-receiver_TeaStore)
      (logback-receiver-accepts-remote-events logback-receiver_TeaStore)
      (logback-receiver-configured-in-logback-xml logback-receiver_TeaStore)
      ;not (has-ips-protection TeaStore)
      ;not (has-serialized-payload-detection TeaStore)
      ;not (has-proper-exception-handling TeaStore)

      (has-server TeaStore tcp-server_TeaStore)
      (server-has-tcp-endpoint tcp-server_TeaStore tcp-endpoint_TeaStore)
      (server-listens-on-port tcp-server_TeaStore)
       

      ;; ==== Added for CVE-2023-44487 =====
      (has-server TeaStore http2-server_TeaStore)
      (has-http2-implementation TeaStore http2-server_TeaStore http2-library_TeaStore)
      (http2-stream-multiplexing-enabled TeaStore http2-server_TeaStore)
     
     
     (http2-server-has-network-interface TeaStore http2-server_TeaStore network-interface_TeaStore)
     (http2-server-public-facing-interface TeaStore network-interface_TeaStore)
     ;(or 
     ;(= (port network-interface_TeaStore) 443)
      (= (port network-interface_TeaStore) 80)
     ;)
     (http2-connections-accepted TeaStore network-interface_TeaStore)

     (http2-server-processes-headers-frames http2-server_TeaStore)
     (http2-server-processes-rst-stream-frame http2-server_TeaStore)
     ;(not (http2-server-has-frame-rate-limiting http2-server_TeaStore))
     
    
     (http2-server-allocates-stream-resources TeaStore http2-server_TeaStore)
     (http2-server-allocates-header-parsing-resources TeaStore http2-server_TeaStore)
     (http2-server-allocates-url-mapping-resources TeaStore http2-server_TeaStore)
     
     (http2-server-allows-immediate-rst-stream TeaStore http2-server_TeaStore)
     ;(not (http2-server-requires-stream-coordination TeaStore http2-server_TeaStore))
     
     ;(not (http2-server-enforces-canceled-request-limits TeaStore http2-server_TeaStore))
     (http2-server-canceled-requests-not-counted-toward-limits TeaStore http2-server_TeaStore)
     
    
     ;(not (http2-server-has-connection-level-pattern-tracking TeaStore http2-server_TeaStore))
     ;(not (http2-server-detects-rapid-creation-cancellation-patterns TeaStore http2-server_TeaStore))
     
     (http2-server-maintains-connections-after-cancellation TeaStore http2-server_TeaStore)
     (http2-server-allows-indefinite-stream-creation TeaStore http2-server_TeaStore)
     
     ;(not (http2-server-implements-goaway-frame-abuse-detection TeaStore http2-server_TeaStore))
     ;(not (http2-server-has-immediate-connection-termination TeaStore http2-server_TeaStore))

     ;(or (and 
     (http2-server-nodejs-implementation http2-library_TeaStore) 
     ;         (or 
     (= (version http2-library_TeaStore) 18000000000) 
     ;    (= (version http2-library_TeaStore) 20000000000)))


     ;     (and (http2-server-nghttp2-implementation http2-library_TeaStore) 
     ;          (<= (version ?http2-library_TeaStore) 1057000000))
     ;     (and (http2-server-netty-implementation http2-library_TeaStore) 
     ;          (<= (version http2-library_TeaStore) 4001100000))
     ;     (http2-server-envoy-implementation http2-library_TeaStore)
     ;     (http2-server-eclipse-jetty-implementation http2-library_TeaStore)
     ;     (and (http2-server-caddy-implementation http2-library_TeaStore) 
     ;           (<= (version http2-library_TeaStore) 2007005000)))
     
    
     ;(not (http2-server-has-rapid-reset-ddos-protection TeaStore http2-server_TeaStore))
     ;(not (http2-server-has-rapid-reset-pattern-detection TeaStore http2-server_TeaStore))
     
     (insufficient-resource-limits TeaStore http2-server_TeaStore)
     ;(not (http2-server-can-handle-rapid-allocation-cancellation-cycles TeaStore http2-server_TeaStore)

    
    
     ;; ==== Added for CVE-2023-44487 =====
     ; 1. Application uses vulnerable versions of Spring Security
     (has-dependency-on-spring-security TeaStore spring-security_TeaStore)
     (= (version spring-security_TeaStore) 6003000003)
     ; 2. Authentication mechanism uses BCryptPasswordEncoder for password verification
     (use-bcrypt-password-encoder TeaStore password_encoder_TeaStore)
    ; 3. System allows or accepts user passwords longer than 72 characters
     (allows-long-passwords TeaStore)
    ;(not (password-length-validation TeaStore))
    ; 5. No additional authentication factors are required (no MFA/2FA enforcement)
    ;(not (multi-fator-auth-enabled TeaStore))
    ;(not (two-factor-auth-enabled TeaStore))
    ; 6. No password length validation or truncation warnings are implemented
    ;(not (password-truncation-warning TeaStore))
    ; 7. No compensating controls
    ;(not (account-lockout-policy TeaStore))
    ;(not (rate-limiting-enabled TeaStore))
    ;(not (anomaly-detection-enabled TeaStore))
    ; 8. Application does not implement pre-hashing mechanisms
    ;(not (pre-hashing-implemented TeaStore))
    ;(not (sha256-pre-hash-enabled TeaStore))


    ;; ==== Added for CVE-2023-44487 =====
    ; 2. Application uses functional web frameworks WebMvc.fn or WebFlux.fn for serving static resources
    ;(or 
    (uses-WebMvc-web-framework TeaStore)
    ;(uses-WebFlux-web-framework TeaStore))
    ; 3. Application explicitly configures RouterFunctions to serve static resources
    (has-router-function-configured TeaStore router-function_TeaStore)
    (router-function-serves-static-resources router-function_TeaStore)
    ; 4. Resource handling configured with FileSystemResource location
    (has-filesystem-resource-configured TeaStore filesystem-resource_TeaStore)
    (points-to-filesystem-path filesystem-resource_TeaStore)
    ; 5. Application process has read access to sensitive files
    (has-filesystem-read-access TeaStore)
    (sensitive-files-accessible TeaStore)
    ; 6. Spring Security HTTP Firewall is NOT enabled
    ;(not (spring-security-http-firewall-enabled TeaStore))
    ; 7. NOT running on Tomcat or Jetty (which would block malicious requests)
    ;(not (runs-on-tomcat TeaStore))
    ;(not (runs-on-jetty TeaStore))
    ; 8. No input validation for URL path parameters
    ;(not (url-path-validation-enabled TeaStore)) 
    ; 9. No WAF rules for path traversal detection
    ;(not (has-WAF-path-traversal-protection TeaStore)) 
    ; 10. File system permissions allow reading outside intended directory
    (filesystem-permissions-allow-traversal TeaStore)
    (located-at sensitive-file1_TeaStore filesystem-path_TeaStore)
    (data-stored-in-file sensitive-file-content1 sensitive-file1_TeaStore)





    ;; ==== Added for CVE-2022-1471 =====
    ; 1. Application uses vulnerable SnakeYAML version (prior to 2.0, specifically 1.30-1.33)
    (has-dependency-on-snakeyaml TeaStore snakeyaml-library_TeaStore)
    (= (version  snakeyaml-library_TeaStore) 1030003) ; versions 1.30+ to < 2.0
    ; 2. Java version vulnerable to JNDI injection (≤ 8u190 or ≤ 11.0.0)
    (implementated-by-java TeaStore  java_TeaStore)
    (= (version  java_TeaStore) 8000006) 
    ; 3. Application accepts external YAML content from untrusted sources
    (has-external-yaml-endpoint TeaStore yaml-endpoint_TeaStore)
    (accepts-untrusted-yaml-input TeaStore)
    ; 4. No input validation on YAML content
    ;(not (has-yaml-input-validation TeaStore))
    ; 5. Uses default Constructor() instead of SafeConstructor
    (uses-default-constructor TeaStore)
    ;(not (uses-safe-constructor TeaStore)) 
    ; 6. No type restrictions during deserialization
    ;(not (has-yaml-type-restrictions TeaStore))   
    ; 7. Sufficient privileges for code execution
    (has-sufficient-code-execution-privilege TeaStore)    
    ; 8. No security controls preventing dangerous class instantiation
    ;(not (has-dangerous-class-instantiation-prevention TeaStore))  
    ; 9. No sandbox restrictions
    ;(not (has-sandbox-restrictions TeaStore))
    ; 10. Network connectivity for exfiltration
    (network-connectivity-available TeaStore)

    (has-receive-endpoint TeaStore yaml-endpoint_TeaStore)

    
    ;; ==== Added for CVE-2025-24813 =====
    ;; 2. Tomcat Server's Default servlet has write permissions enabled - writes enabled for the default servlet (disabled by default)
    (tomcat-has-default-servlet TeaStore default-servlet_TeaStore)
    (tomcat-default-servlet-write-enabled TeaStore default-servlet_TeaStore)
    ;; 3. Partial PUT request support is enabled (enabled by default) - support for partial PUT (enabled by default) 
    (partial-put-request-enabled TeaStore)
    ;; 4. Attacker has knowledge of public upload directories
    (has-public-directory TeaStore public-directory_TeaStore)
    (public-directory-exposed TeaStore public-directory_TeaStore)

    ;; distinguished preconditions for information disclosure and elevation of priviledge (RCE)
    ;; (or 
    ;;      (and ;;for information disclosure
    ;; 5. Security sensitive directories are sub-directories of public directories - a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads  
    (public-directory-has-sensitive-subdirectory public-directory_TeaStore sensitive-directory_TeaStore)
    (located-at sensitive-file2_TeaStore sensitive-directory_TeaStore)
    ;; 6. Attacker has knowledge of sensitive filenames - attacker knowledge of the names of security sensitive files being uploaded 
    (sensitive-filename-exposed TeaStore sensitive-file2_TeaStore)
    ;; 7. security sensitive files are uploaded via partial PUT requests - the security sensitive files also being uploaded via partial put
    (sensitive-file-partial-put-uploaded-enabled TeaStore sensitive-file2_TeaStore)
    ;;)
    ;; (and ;;for code excution
    ;; 8. For remote code execution: application uses Tomcat's file-based session persistence with default storage location -  application was using Tomcat's file based session persistence with the default storage location 
    (tomcat-file-based-session-persistence-enabled TeaStore tomcat_TeaStore) 
    (tomcat-default-session-storage-location TeaStore tomcat_TeaStore)
    ;;  ) )
    ;; 10. HTTP PUT method accessible to unauthenticated users
    (http-put-method-accessible TeaStore)
        
    ;; 11. No WAF or security controls blocking malicious PUT requests
    ; (not (WAF-malicious-request-block TeaStore))
    ; (not (security-controls-path-manipulation TeaStore))
        
    ;; 12. Application processes filenames with internal dots without proper normalization
    ; (not (has-proper-path-normalization-for-filename TeaStore))
    ; (not (has-proper-path-equivalence-validation-for-filename TeaStore))

     (data-stored-in-file sensitive-file-content2 sensitive-file2_TeaStore)
    
     (jsp-extension file-extension1) 
    ;(jspx-extension file-extension1)
     (tomcat-has-jsp-engine tomcat_TeaStore jsp-engine_TeaStore)
     (tomcat-jsp-engine-enabled TeaStore tomcat_TeaStore) 

     (has-tomcat-process TeaStore tomcat-process_TeaStore)

    ;; ==== Added for CVE-2023-2976 =====
 
     (guava-library guava-library_TeaStore)
     (has-library TeaStore guava-library_TeaStore)
     (= (version guava-library_TeaStore) 31001000000)
     (uses-filebackedoutputstream TeaStore)
     (uses-uncontrolled-createtempfile TeaStore)
     (java-tmpdir-set-to-world-writable TeaStore)
     (has-os TeaStore  host-os_TeaStore)
     (world-readable-tempdir-permissions host-os_TeaStore)
     (world-writable-tempdir-permissions host-os_TeaStore)
     ;not (container-isolated TeaStore)
     ;not(os-sandbox-isolated TeaStore)
     ;not(uses-per-user-temp-directory TeaStore)
     ;not(temp-directory-acl-protected TeaStore)
     ;not(temp-directory-mount-restricted TeaStore)
     (uses-predictable-temp-filenames TeaStore)
     (writes-sensitive-data-to-temp TeaStore)
     (temp-directory-under-surveillance temporary-directory_TeaStore)


    ;; ==== Added for CVE-2024-38809 =====
     ;; 1. Application uses vulnerable Spring Framework spring-web module
     (has-framework TeaStore spring-framework1)
     (spring-web-module spring-framework1)
    
     ;; 2. Application processes ETags from If-Match or If-None-Match headers
     (has-http-endpoint TeaStore  http-endpoint_TeaStore)
     (has-etag-handler TeaStore etag-handler_TeaStore)
     (processes-if-match-headers TeaStore etag-handler_TeaStore)
     (processes-if-none-match-headers TeaStore etag-handler_TeaStore)
     
     ;; 3. ETag parsing logic lacks proper validation
     ;not (has-etag-validation TeaStore etag-handler_TeaStore)
     ;not (has-etag-size-limits TeaStore etag-handler_TeaStore)
     ;not (has-etag-complexity-limits TeaStore etag-handler_TeaStore)
     
     ;; 4. Application exposes HTTP endpoints to untrusted users
     (publicly-accessible http-endpoint_TeaStore)
     ;not (has-restrictive-access-controls http-endpoint_TeaStore)
     
     ;; 5. No size limits on If-Match or If-None-Match headers
     ;not (has-header-size-limits TeaStore http-endpoint_TeaStore)
     ;not (has-framework-header-limits pring-framework1)
     ;not (has-servlet-container-limits TeaStore)
     
     ;; 6. No rate limiting or request throttling
     ;not (has-http-rate-limiting TeaStore http-endpoint_TeaStore)
     ;not (has-request-throttling TeaStore http-endpoint_TeaStore)
     
     ;; 7. No custom input validation filters
     ;not (has-input-validation-filters TeaStore)
     ;not (has-etag-validation-middleware TeaStore)
     
     ;; 8. No WAF/IPS protection
     ;not (has-waf-protection TeaStore)
     ;not (has-ips-protection TeaStore)
     ;not (has-etag-header-detection-rules TeaStore)
     
     ;; 9. Shared server resources without isolation
     (has-shared-resources TeaStore)
     ;not (has-resource-isolation TeaStore)
     
     ;; 10. Shared thread pool across endpoints
     (has-shared-thread-pool TeaStore)
     ;not (has-endpoint-isolation TeaStore)

    ;; ==== Added for CVE-2024-47072 =====
     ;1. Application uses vulnerable XStream version
     (has-library TeaStore XStreamLibrary_TeaStore)
     (xstream-library XStreamLibrary_TeaStore)
     (= (version XStreamLibrary_TeaStore) 1004010009) ;version <= 1.4.20
     
     ;2. Application configures XStream to use BinaryStreamDriver
     (has-binary-stream-driver TeaStore binary-stream-driver_TeaStore)
     (binary-stream-driver binary-stream-driver_TeaStore)
     (xstream-uses-driver XStreamLibrary_TeaStore binary-stream-driver_TeaStore)
    
     ;3. Application accepts and processes attacker-controlled binary input streams 
     (accepts-binary-input TeaStore API-endpoint_TeaStore)
     (processes-untrusted-input TeaStore API-endpoint_TeaStore)
     
     ;4. Application lacks robust input validation or integrity checks
     ;not (api-endpoint-has-integrity-checks TeaStore API-endpoint_TeaStore)
     
     ;5. Application does not implement StackOverflowError exception handling
     ;not (has-stackoverflow-exception-handling TeaStore)
     
     ;6. Application's runtime permits deeply nested structures without safeguards
     ;not (has-defense-in-depth-safeguards TeaStore)
     ;not (has-recursive-structure-limits TeaStore)
     
     ;7. Application lacks effective JVM stack size restrictions
     ;not (has-jvm-stack-size-restrictions TeaStore)
     ;not (has-sufficient-stack-limits TeaStore)
     
     ;8. Application lacks limits on input stream size or complexity
     ;not (has-input-stream-size-limits TeaStore)
     ;not (has-structural-complexity-limits TeaStore)
     
     ;9. Application lacks compensating security mechanisms
     ;not (has-sandboxing TeaStore)
     ;not (has-deserialization-whitelist TeaStore)
     ;not (has-waf-binary-filtering TeaStore)

    ;; ==== Added for CVE-2023-33202 =====
    ; 1. vulnerable Bouncy Castle present: version < 1.73.0
    (has-library TeaStore BCLibrary_TeaStore)
    (bouncycastle-library BCLibrary_TeaStore)
    (= (version BCLibrary_TeaStore) 1007200011) ; version < 1.73.0 (encoding documented above)

    ; 2. application code invokes or forwards to PEMParser
    (uses-pemparser TeaStore)

    ; 3. application exposes interface(s) that accept PEM/ASN.1 input
    (has-pem-endpoint TeaStore pem-endpoint_TeaStore)
    (accepts-pem-input TeaStore pem-endpoint_TeaStore)

    ; 4. parsing performed in-process on same JVM heap
    (parser-in-process TeaStore)
    (parser-shares-jvm-heap TeaStore)

    ; 5. no effective pre-validation/ASN.1 structural checks
    ;not (endpoint-has-content-type-enforcement TeaStore pem-endpoint_TeaStore)
    ;not (endpoint-has-asn1-sanity-checks TeaStore pem-endpoint_TeaStore)
    ;not (endpoint-rejects-suspicious-pem-patterns TeaStore pem-endpoint_TeaStore)

    ; 6. lacks request/resource controls (file-size, depth, timeouts, per-request caps)
    ;not (endpoint-has-file-size-limits TeaStore pem-endpoint_TeaStore)
    ;not (endpoint-has-asn1-depth-limits TeaStore pem-endpoint_TeaStore)
    ;not (endpoint-has-parser-timeouts TeaStore pem-endpoint_TeaStore)
    ;not (endpoint-has-per-request-memory-caps TeaStore pem-endpoint_TeaStore)

    ; 7. endpoints reachable with low/no privileges or insufficient rate-limiting
    (endpoint-reachable-to-attackers TeaStore pem-endpoint_TeaStore)
    ;not (endpoint-rate-limited TeaStore pem-endpoint_TeaStore)

    ; 8. JVM/container runtime lacks heap isolation / cgroup limits
    ;not (has-cgroup-memory-limit TeaStore)
    ;not (has-pod-memory-limit TeaStore)
    (single-jvm-hosting-critical-services TeaStore)

    ; 9. no sandboxing or process isolation for untrusted parsing
    ;not (parsing-sandboxed TeaStore)

    ; 10. error handling does not gracefully contain OutOfMemoryError
    ;not (has-circuit-breaker-for-oom TeaStore)
    ;not (graceful-degradation-on-oom TeaStore)

    ; 11. no upstream protections (WAF / upload policies / scanners)
    ;not (has-waf-protection TeaStore)
    ;not (has-upload-policy-scanner TeaStore pem-endpoint_TeaStore)

    ;; ==== Added for CVE-2023-46589 =====
     (has-reverse-proxy TeaStore reverse-proxy_TeaStore)
     (forwards-requests reverse-proxy_TeaStore tomcat_TeaStore)
     
     ; 3. Application accepts HTTP/1.1 requests with Transfer-Encoding: chunked
     (accepts-chunked-encoding TeaStore)
     (permits-trailer-headers reverse-proxy_TeaStore)
     
     ; 4. Mismatched parsing between reverse proxy and Tomcat
     (mismatched-parsing reverse-proxy_TeaStore tomcat_TeaStore)
     (mismatched-trailer-handling reverse-proxy_TeaStore tomcat_TeaStore)
     (mismatched-header-limits reverse-proxy_TeaStore tomcat_TeaStore)
     
     ; 5. Reverse proxy forwards trailer header bytes without normalization
     ;not (normalizes-trailer-headers reverse-proxy_TeaStore)
     ;not (rejects-oversized-trailers reverse-proxy_TeaStore)
     ;not (truncates-oversized-trailers reverse-proxy_TeaStore)
     
     ; 6. Backend connection allows reuse/keep-alive/pipelining
     (allows-connection-reuse reverse-proxy_TeaStore tomcat_TeaStore)
     (allows-keep-alive reverse-proxy_TeaStore tomcat_TeaStore)
     (allows-pipelining reverse-proxy_TeaStore tomcat_TeaStore)
     
     ; 7. Application exposes target endpoints reachable by attacker
     ; 8. Endpoints do not enforce strict per-request authentication
     ;not (strict-per-request-auth http-endpoint_TeaStore)
     
     ; 9. Application lacks request smuggling detection mechanisms
     ;not (has-waf-smuggling-detection TeaStore)
     ;not (has-ips-oversized-trailer-rules TeaStore)
     ;not (rejects-malformed-trailers reverse-proxy_TeaStore)
     ;not (has-request-canonicalization TeaStore)

     
     (bond-to-user-account user1 sensitive-order1)
     (cacheable-resource cacheresource1)
     (has-cached-resource cacheresource1)
     (has-application-cache TeaStore cache1_TeaStore)


    ;;;(1).====================================END===================================;;;
  



    ;;;(2).================================USER STATE================================;;;
    ;; === for CVE-20224-12798 ===
    (user-visits-site user1 email-site)
    ;;(use-browser browser-chrome)
     
    ;;==== Added for CVE_2024_22243 AP 1&2 =====
    (user-has-valid-credentials-application user1 user1-password_TeaStore TeaStore)
    (is-default-browser browser-chrome)

    ;; ==== Added for CVE-2023-44487 =====
    (user-needs-to-use-application user1 TeaStore)

    ;; ==== Added for CVE-2023-33202 =====
    (has-account user1 TeaStore)
    
    ;; ==== Added for CVE-2023-46589 =====
    (user-http-request user-http-request1)
    ;;;(2).====================================END===================================;;;




    ;;;(3).=============================Attacker Capability==========================;;;
     ;; === for CVE-20224-12798 ===
    ; (malicious-file malicious-logback-config)
    (env-var-logback-set-script malicious-logback-env-var-set-script1)    
    
    ;; ==== Added for CVE-2024-38286 AP 1&2 =====
    (tls-flood-script tomcat-tls-flood-script1)
    (tomcat-tls-flood-script tomcat-tls-flood-script1)
    (tls-initial-handshake-request-script tomcat-tls-initial-handshake-request-script1)
    (tls-renegotiation-script tomcat-tls-renegotiation-script1)

    ;; ==== Added for CVE_2023_34055 AP 1&2 =====
    (http-flood-script http-flood-script1)


    ;; ==== Added for CVE-2024-34447 AP 1&2 =====
    (controlled-server-ip-address  malicious-server1 malicious-server-address1)

    ;; ==== Added for CVE-2025-22223 AP2 =====
    (online-brute-force-script online-brute-force-script1)

     ;; ==== Added for CVE-2023-46589 AP2 =====
    (smuggling-trigger-http-request smuggling-trigger-request1)
    (smuggling-http-request-http  smuggling-request-cache-poisoning1)
    (smuggling-http-request-http  smuggling-request-hijack1)
    (smuggling-http-request-cache-poisoning  smuggling-request-cache-poisoning1)
    (smuggling-http-request-hijack smuggling-request-hijack1)

   
    ;;;(3).=====================================END================================;;;
  )
 
  (:goal (and 
  (spoofing TeaStore)))
  (:metric minimize (total-cost)))
