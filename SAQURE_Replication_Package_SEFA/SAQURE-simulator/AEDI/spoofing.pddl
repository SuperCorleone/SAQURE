(define (problem AEDI-spoofing)
  (:domain AED)
  
  (:objects
    attacker1 - attacker
    
    ;;;(1).=================================Application Configuration====================;;;
    ;;; Entity declaration ;;;
    
    SEFA - application ;application
    logback_SEFA - logback
    janino-library_SEFA - java-library
    legit-logback-config - logback-config
    malicious-logback-config - logback-config
    config-dir_SEFA - path
    gmail - comchannel
    browser-chrome - browser
    browser-IE - browser
    email-site - site
    logback-env-var1 - env-var


   ;; === Added for CVE-2024-38286==
    tomcat_SEFA - tomcat
    tls-connector_SEFA - tls-connector

   ;; ==== Added for CVE-2024-38820 ====;;
   databinder_SEFA - data-binder
   ;; Locale Configuration
   locale-config_SEFA - locale-config
   ;; Security Patterns
   admin-field-pattern - disallowed-pattern
  
  ;; ==== Added for CVE-2022-1471 =====
  snakeyaml-library_SEFA - snakeyaml-library
  java_SEFA - software
  yaml-endpoint_SEFA - yaml-endpoint
  java-gadget-class_SEFA - java-gadget-class
  yaml-constructor_SEFA - yaml-constructor


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
   redirect-url1 - redirect-url     ;https://sefa.com/redirect?url=https://sefa.com:80@evil.com
   valiation-pass-pyload1 - payload-string      ;https://sefa.com:80@evil.com
   ;user1-password_SEFA - credential
   user1-password_SEFA - password
   UriComponentsBuilder - url-parser
   url-setting-endpoint1  - endpoint
   Twitter Facebook - social-media
   internal-resource-address1 - internal-address ;http://localhost:8080/internal-data
   sensitive-file-name1 - sensitive-information
   
   ;; ==== Added for CVE-2024-38820 ====;;
   spring-framework1 - spring-framework
   web-controller_SEFA - web-controller
   attacker-account_SEFA - account
   attacker-credentials_SEFA - credential
   attacker-session_SEFA - session-cookie

   crafted-locale-bypass-url1 - locale-bypass-url
   turkish-i-param - locale-bypass-parameter  ; İsAdmin=true parameter
   transformed-param1 - transformed-parameter  ; i̇sadmin result

   i̇sadmin - parameter-name

  ;; ==== Added for CVE-2023-34055 ====;;
   springboot_SEFA - spring-boot
   http-flood-script1 - script

  ;; ==== Added for CVE-2024-34447 ====;;
  bouncy-castle-lib_SEFA - bouncy-castle
  bcjsse-component_SEFA - bcjsse
  vulnerable-dns-server1 - dns-server
  legit-server1_SEFA - legitimate-server
  legit-server-address1 - legitimate-ip-address
  malicious-server-address1 - malicious-ip-address
  attacker-domain1 - controlled-domain
  attacker-cert1 - ssl-certificate
  socket_SEFA - ssl-socket
  SEFA-microservice - legitimate-service
  
 ;; ==== Added for CVE-2022-40150 ====;;
  jettison-library_SEFA - java-library
  malicious-jettison-payload1 - json-payload
  API-endpoint_SEFA - api-endpoint
  http-post-request1 - http-post-request
  SOAP-endpoint_SEFA - soap-endpoint
  malicious-xml-payload1 - xml-payload


;; ==== Added for CVE-2023-6378====;;
  logbacklib_SEFA - java-library
  logback-receiver_SEFA - logback-receiver
  tcp-endpoint_SEFA - tcp-endpoint
  serialized-payload1 - serialized-payload
  tcp-connection_SEFA - tcp-connection
  tcp-server_SEFA - tcp-server

;; ==== Added for CVE-2023-44487====;;
  http2-server_SEFA - http2-server
  http2-library_SEFA - http2-library
  http2-connection_SEFA - http2-connection
  tls-endpoint_SEFA - tls-endpoint
  tls-connection_SEFA - tls-connection
  network-interface_SEFA - network-interface
  http2-settings-frame1 - http2-settings-frame
  http2-settings-ack-frame1 - http2-settings-ack-frame
  rst-stream-frame1 - rst-stream-frame
  stream-limit_SEFA - stream-limit
  stream-batch1 - stream-batch
  server-resource_SEFA - server-resource 

;; ==== Added for CVE-2025-22228====;;
  spring-security_SEFA - spring-security
  password_encoder_SEFA - password-encoder
  online-brute-force-script1 - script
  user1-password-hash_SEFA - password-hash
  login-request1_SEFA - login-request 
  password-encoder_SEFA - password-encoder

;; ==== Added for CVE_2024_38816====;;
  router-function_SEFA - router-function
  resource-handler_SEFA - resource-handler
  filesystem-resource_SEFA - filesystem-resource
  path-traversal-url1 - path-traversal-url
  path-traversal-payload1 - path-traversal-payload 
  sensitive-file1_SEFA - sensitive-file
  filesystem-path_SEFA - filesystem-path
  sensitive-file-content1 - sensitive-information


;; ==== Added for CVE-2022-1471 =====
  command-execution-logic1 - command-execution-logic
  rmi-service1 - rmi-service 
  ldap-service1 - ldap-service
  yaml-payload1 -  yaml-payload
  malicious-java-class1 - java-class
  jndi-endpoint1 - jndi-endpoint

;; ==== Added for CVE-2025-24813 =====
  default-servlet_SEFA - default-servlet
  public-directory_SEFA - public-directory
  sensitive-directory_SEFA - sensitive-directory
  sensitive-file2_SEFA - sensitive-file
  sensitive-file-content2 - sensitive-information
  http-get-request1 - http-get-request
  http-put-request1 - http-put-request
  malicious-content1 - malicious-content
  content-range-headers1 - content-range-headers
  file-extension1 - file-extension
  jsp-engine_SEFA - jsp-engine
  web-shell-script1 - web-shell-script
  tomcat-process_SEFA - tomcat-process

;; ====== added for CVE-2023-2976 ======
  guava-library_SEFA - java-library
  temporary-directory_SEFA - temporary-directory
  host-os_SEFA - host-os
  filename-pattern_SEFA - filename-pattern
  sensitive-system-file_SEFA - sensitive-system-file
  temporary-file_SEFA - temporary-file
  symbolic-link1 - symbolic-link
  controlled-file1 - controlled-file

;; ====== added for CVE-2024-38809 ======
  http-endpoint_SEFA - http-endpoint
  etag-handler_SEFA - etag-handler
  etag-value_SEFA - etag-value

;; ====== added for CVE-2024-47072 ======
  XStreamLibrary_SEFA - java-library
  binary-stream-driver_SEFA - binary-stream-driver
  binary-payload1 - binary-payload 

;; ====== added for CVE-2023-33202 ======
  BCLibrary_SEFA - java-library
  pem-endpoint_SEFA - pem-endpoint 
  pem-payload1 - pem-payload
  asn1-structure_SEFA - asn1-structure
  pem-file1 - pem-file


;; ====== added for CVE-2023-46589 ======
  reverse-proxy_SEFA - reverse-proxy
  trailer-header1 - trailer-header 
  user-session1 - user-session
  sensitive-order1 -  sensitive-information
  user-http-request1 - http-request
  http-response_SEFA - http-response
  cacheresource1 - cached-resource
  cache-poison-payload1 - cache-poison-payload
  cache1_SEFA - application-cache
  smuggling-trigger-request1 - http-request
  smuggling-request-cache-poisoning1 - http-request
  smuggling-request-hijack1 - http-request

  
  )

  (:init
    

    (= (total-cost) 0)


   
    ;;;(1).=================================Application Configuration====================;;;
    ;; === for CVE-20224-12798 ===
    ;; entry points: system state
    (has-logback SEFA logback_SEFA)
     
    (= (version logback_SEFA) 1004000002)

    (janino-evaluator-enabled SEFA logback_SEFA)
   
    (has-library SEFA janino-library_SEFA)
    (janino-library janino-library_SEFA )
     
    (dynamic-config-loading-enabled SEFA logback_SEFA)
    

    (has-config-dir SEFA config-dir_SEFA)
    (has-access user1 config-dir_SEFA)
    (has-write-access user1 config-dir_SEFA)


    ;not (has-code-execution-restriction SEFA logback_SEFA)
    (legitimate-file legit-logback-config) 
    (located-at legit-logback-config config-dir_SEFA)
    ;not (has-integrity-check SEFA logback_SEFA legit-logback-config)
    ;not (has-signature-verification SEFA logback_SEFA legit-logback-config)
    (has-controllable-env-vars SEFA)
     
    (script-execution-prompt-enabled SEFA)  ;; one key for controlling branches

   ;; ==== Added for CVE-2024-38286 AP 1&2 =====
    (has-tomcat SEFA tomcat_SEFA)
    (tomcat-has-tls-connector SEFA tomcat_SEFA tls-connector_SEFA)
    (= (version tomcat_SEFA) 11000000001)
    (tomcat-tls-renegotiation-enabled SEFA tomcat_SEFA tls-connector_SEFA)
    (has-memory-limitation  SEFA tomcat_SEFA)
    ;not (has-memory-protection-mechanisms SEFA)
    ;not (max-connection-restriction SEFA)
    ;not (firewall-connection-restriction SEFA)
    ;not (IDS-monitoring SEFA)
    ;not (IPS-monitoring SEFA)
    ;not (WAF-monitoring SEFA) 

    ;; ==== Added for CVE_2024_22243 AP 1&2 =====
    (has-dependency-on-spring-framework SEFA spring-framework1)
    (=(version spring-framework1) 6001000001)
    (has-dependency-on-vulnerable-paser SEFA  UriComponentsBuilder)
    (has-external-settingable-endpoint SEFA url-setting-endpoint1)
    (url-redirect-enabled SEFA)
    ;not (url-endpoint-setting-restriction SEFA url-setting-endpoint1)
     ;(url-endpoint-protocol-restriction SEFA url-setting-endpoint1)
     ;(url-endpoint-path-restriction SEFA url-setting-endpoint1)
     ;(url-endpoint-points-restriction SEFA url-setting-endpoint1)

    (external-resource-accessable SEFA)
    (internal-resource-accessable SEFA)
    (vulnerable-host-validation SEFA)
    ;(depend-blacklist-host-validation SEFA)
    ;(canonicalization-parse-url SEFA)
    
    ;not (anti-redirect-protection SEFA)

    ;not (WAF-malicious-request-bloack SEFA)
    ;not (IPS-malicious-request-bloack SEFA)
     
    (data-saved-in-internal-address sensitive-file-name1 internal-resource-address1)


  ;; ==== Added for CVE_2024_38820 AP 1&2 =====
   (has-vulnerable-databinder SEFA databinder_SEFA)
   (databinder-parameter-binding-enabled SEFA databinder_SEFA)

   (has-disallowed-databinder-fields-configuration SEFA)

   (databinder-has-write-access-to-properties SEFA databinder_SEFA)
   ;not (databinder-has-additional-input-validation-layer SEFA databinder_SEFA)      
   (databinder-relies-on-case-insensitive-field-matching SEFA databinder_SEFA)
      

   (has-locale-configuration SEFA locale-config_SEFA)
   (processes-requests-in-locale-context SEFA)
   (has-locale-specific-exceptions SEFA)
   (locale-has-special-case-conversion SEFA)
   (has-vulnerable-locale-transformation SEFA)
   
   (locale-dependent-string-processing SEFA)
   ;not (explicit-locale-specification-in-lowercase SEFA)

   (has-web-controller-accept-http-post-user-input SEFA web-controller_SEFA)
   (accepts-user-controlled-parameter-names SEFA)

   ;not (has-additional-field-access-controls SEFA)
   ;not (has-parameter-name-sanitization SEFA)
   ;not (has-WAF-case-manipulation-rules SEFA)
   ;not (has-input-filter-case-bypass-detection SEFA)

   ;; ==== Added for CVE_2023_34055 AP 1&2 =====
   ;1. Application runs vulnerable Spring Boot versions (2.7.0-2.7.17, 3.0.0-3.0.12, or 3.1.0-3.1.5)
  (has-spring-boot SEFA springboot_SEFA)
   (= (version springboot_SEFA) 2007010001) 

  ;2. Application uses Spring MVC or Spring WebFlux web framework
  ;(or (spring-boot-has-mvc SEFA springboot_SEFA)
     (spring-boot-has-webflux SEFA springboot_SEFA)
  ;   )
  
   ;3. org.springframework.boot:spring-boot-actuator dependency is present on the classpath
  (has-actuator-dependency SEFA springboot_SEFA)

  ;4. Web metrics collection is enabled (management.metrics.enable.http.server.requests=true by default)
  (web-metrics-enabled SEFA springboot_SEFA)

  ;5. Application accepts and processes HTTP requests from external sources
  (accepts-external-http-requests SEFA)

  ;6. No rate limiting or request throttling mechanisms are implemented
  ;no (max-connection-restriction SEFA)

  ;7. Application endpoints are accessible to attackers (no network-level filtering)
  (actuator-endpoints-accessible SEFA)
  ;no (firewall-connection-restriction SEFA) 
  
  ;8. Web observations and metrics gathering functionality is activ
  (web-observations-active SEFA springboot_SEFA)


   ;9. No monitoring or alerting systems detect unusual request patterns
  ;no (IDS-monitoring SEFA) 
  ;no (IPS-monitoring SEFA) 
  ;no (WAF-monitoring SEFA)

  ;10. Application lacks resource consumption controls or request size limits
  ;no (resource-consumption-controls SEFA) 
  ;no (request-size-limits SEFA) 


  ;; ==== Added for CVE_2023_34055 AP 1&2 =====
  ;; Application and Bouncy Castle setup
    (has-bouncy-castle SEFA bouncy-castle-lib_SEFA)
    (bcjsse-enabled SEFA bouncy-castle-lib_SEFA bcjsse-component_SEFA)
    (endpoint-identification-enabled SEFA bcjsse-component_SEFA)
    (ssl-socket-without-explicit-hostname SEFA)
    (https-connections-trigger-dns-resolution SEFA)
    (dns-traffic-interception-allowed SEFA)
    
    ;; Bouncy Castle version (before 1.78 - vulnerable)
    (= (version bouncy-castle-lib_SEFA) 1077000000) ; version 1.77
    
    ;; Absence of security measures (using NOT in preconditions)
    ; Note: These are checked as (not ...) in preconditions
    ; (not (additional-certificate-validation SEFA))
    
    ;; Legitimate server setup
    (legitimate-server-ip-address legit-server1_SEFA legit-server-address1)

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
      
      (has-library SEFA jettison-library_SEFA)
      (jettison-library jettison-library_SEFA)
      (= (version jettison-library_SEFA) 1005001000)
      (has-api-endpoint SEFA API-endpoint_SEFA)
      (has-receive-endpoint SEFA API-endpoint_SEFA)
      (accepts-json-input SEFA API-endpoint_SEFA)

      ;not (api-endpoint-has-input-validation SEFA API-endpoint_SEFA)
      ;not (api-endpoint-has-input-size-limits SEFA API-endpoint_SEFA)
      ;not (api-endpoint-has-complexity-limits SEFA API-endpoint_SEFA)
      ;not (api-endpoint-has-input-sanitization SEFA API-endpoint_SEFA)
      ;not (api-endpoint-has-preprocessing-detection SEFA API-endpoint_SEFA)
      ;not (has-heap-memory-consumption-limits SEFA)
      ;not (has-heap-memory-monitoring SEFA)
      ;not (has-memory-consumption-limits SEFA)
      ;not (has-memory-monitoring SEFA)
      ;not (has-heap-memory-isolation SEFA)
      ;not (has-heap-memory-quotas SEFA)
      ;not (has-rate-limiting SEFA API-endpoint_SEFA)
      ;not (has-throttling-mechanisms SEFA API-endpoint_SEFA)
      ;not (has-waf-protection SEFA)
      ;not (has-waf-json-payload-detection SEFA)
    
      ;;==== for AP 2===
      (has-receive-endpoint SEFA SOAP-endpoint_SEFA)
      (has-soap-endpoint SEFA SOAP-endpoint_SEFA)

      ;; ==== Added for CVE_2022_40149 AP 1&2 =====
      ;not (has-stack-memory-consumption-limits SEFA )
      ;not (has-stack-memory-monitoring SEFA)
      ;not (has-stack-memory-isolation SEFA)
      ;not (has-stack-memory-quotas SEFA)

      ;; ==== Added for CVE-2023-6378 =====
      (has-library SEFA logbacklib_SEFA)
      (logback-library logbacklib_SEFA)
      (= (version logbacklib_SEFA) 1004011000) 
      (has-receiver-component SEFA logback-receiver_SEFA)
      (logback-receiver-deployed logback-receiver_SEFA)
      (logback-receiver-configured logback-receiver_SEFA)
      (logback-receiver-has-tcp-endpoint SEFA  tcp-endpoint_SEFA)
      (logback-receiver-listens-on-port logback-receiver_SEFA  tcp-endpoint_SEFA)
      (tcp-endpoint-external-access-allowed  tcp-endpoint_SEFA)
      (tcp-endpoint-firewall-permits-inbound  tcp-endpoint_SEFA)
      ;not (has-deserialization-validation SEFA)
      ;not (has-input-sanitization SEFA)
      ;not (has-deserialization-filtering SEFA)
      ;not (logback-receiver-requires-authentication logback-receiver_SEFA)
      (logback-receiver-accepts-remote-events logback-receiver_SEFA)
      (logback-receiver-configured-in-logback-xml logback-receiver_SEFA)
      ;not (has-ips-protection SEFA)
      ;not (has-serialized-payload-detection SEFA)
      ;not (has-proper-exception-handling SEFA)

      (has-server SEFA tcp-server_SEFA)
      (server-has-tcp-endpoint tcp-server_SEFA tcp-endpoint_SEFA)
      (server-listens-on-port tcp-server_SEFA)
       

      ;; ==== Added for CVE-2023-44487 =====
      (has-server SEFA http2-server_SEFA)
      (has-http2-implementation SEFA http2-server_SEFA http2-library_SEFA)
      (http2-stream-multiplexing-enabled SEFA http2-server_SEFA)
     
     
     (http2-server-has-network-interface SEFA http2-server_SEFA network-interface_SEFA)
     (http2-server-public-facing-interface SEFA network-interface_SEFA)
     ;(or 
     ;(= (port network-interface_SEFA) 443)
      (= (port network-interface_SEFA) 80)
     ;)
     (http2-connections-accepted SEFA network-interface_SEFA)

     (http2-server-processes-headers-frames http2-server_SEFA)
     (http2-server-processes-rst-stream-frame http2-server_SEFA)
     ;(not (http2-server-has-frame-rate-limiting http2-server_SEFA))
     
    
     (http2-server-allocates-stream-resources SEFA http2-server_SEFA)
     (http2-server-allocates-header-parsing-resources SEFA http2-server_SEFA)
     (http2-server-allocates-url-mapping-resources SEFA http2-server_SEFA)
     
     (http2-server-allows-immediate-rst-stream SEFA http2-server_SEFA)
     ;(not (http2-server-requires-stream-coordination SEFA http2-server_SEFA))
     
     ;(not (http2-server-enforces-canceled-request-limits SEFA http2-server_SEFA))
     (http2-server-canceled-requests-not-counted-toward-limits SEFA http2-server_SEFA)
     
    
     ;(not (http2-server-has-connection-level-pattern-tracking SEFA http2-server_SEFA))
     ;(not (http2-server-detects-rapid-creation-cancellation-patterns SEFA http2-server_SEFA))
     
     (http2-server-maintains-connections-after-cancellation SEFA http2-server_SEFA)
     (http2-server-allows-indefinite-stream-creation SEFA http2-server_SEFA)
     
     ;(not (http2-server-implements-goaway-frame-abuse-detection SEFA http2-server_SEFA))
     ;(not (http2-server-has-immediate-connection-termination SEFA http2-server_SEFA))

     ;(or (and 
     (http2-server-nodejs-implementation http2-library_SEFA) 
     ;         (or 
     (= (version http2-library_SEFA) 18000000000) 
     ;    (= (version http2-library_SEFA) 20000000000)))


     ;     (and (http2-server-nghttp2-implementation http2-library_SEFA) 
     ;          (<= (version ?http2-library_SEFA) 1057000000))
     ;     (and (http2-server-netty-implementation http2-library_SEFA) 
     ;          (<= (version http2-library_SEFA) 4001100000))
     ;     (http2-server-envoy-implementation http2-library_SEFA)
     ;     (http2-server-eclipse-jetty-implementation http2-library_SEFA)
     ;     (and (http2-server-caddy-implementation http2-library_SEFA) 
     ;           (<= (version http2-library_SEFA) 2007005000)))
     
    
     ;(not (http2-server-has-rapid-reset-ddos-protection SEFA http2-server_SEFA))
     ;(not (http2-server-has-rapid-reset-pattern-detection SEFA http2-server_SEFA))
     
     (insufficient-resource-limits SEFA http2-server_SEFA)
     ;(not (http2-server-can-handle-rapid-allocation-cancellation-cycles SEFA http2-server_SEFA)

    
    
     ;; ==== Added for CVE-2023-44487 =====
     ; 1. Application uses vulnerable versions of Spring Security
     (has-dependency-on-spring-security SEFA spring-security_SEFA)
     (= (version spring-security_SEFA) 6003000003)
     ; 2. Authentication mechanism uses BCryptPasswordEncoder for password verification
     (use-bcrypt-password-encoder SEFA password_encoder_SEFA)
    ; 3. System allows or accepts user passwords longer than 72 characters
     (allows-long-passwords SEFA)
    ;(not (password-length-validation SEFA))
    ; 5. No additional authentication factors are required (no MFA/2FA enforcement)
    ;(not (multi-fator-auth-enabled SEFA))
    ;(not (two-factor-auth-enabled SEFA))
    ; 6. No password length validation or truncation warnings are implemented
    ;(not (password-truncation-warning SEFA))
    ; 7. No compensating controls
    ;(not (account-lockout-policy SEFA))
    ;(not (rate-limiting-enabled SEFA))
    ;(not (anomaly-detection-enabled SEFA))
    ; 8. Application does not implement pre-hashing mechanisms
    ;(not (pre-hashing-implemented SEFA))
    ;(not (sha256-pre-hash-enabled SEFA))


    ;; ==== Added for CVE-2023-44487 =====
    ; 2. Application uses functional web frameworks WebMvc.fn or WebFlux.fn for serving static resources
    ;(or 
    (uses-WebMvc-web-framework SEFA)
    ;(uses-WebFlux-web-framework SEFA))
    ; 3. Application explicitly configures RouterFunctions to serve static resources
    (has-router-function-configured SEFA router-function_SEFA)
    (router-function-serves-static-resources router-function_SEFA)
    ; 4. Resource handling configured with FileSystemResource location
    (has-filesystem-resource-configured SEFA filesystem-resource_SEFA)
    (points-to-filesystem-path filesystem-resource_SEFA)
    ; 5. Application process has read access to sensitive files
    (has-filesystem-read-access SEFA)
    (sensitive-files-accessible SEFA)
    ; 6. Spring Security HTTP Firewall is NOT enabled
    ;(not (spring-security-http-firewall-enabled SEFA))
    ; 7. NOT running on Tomcat or Jetty (which would block malicious requests)
    ;(not (runs-on-tomcat SEFA))
    ;(not (runs-on-jetty SEFA))
    ; 8. No input validation for URL path parameters
    ;(not (url-path-validation-enabled SEFA)) 
    ; 9. No WAF rules for path traversal detection
    ;(not (has-WAF-path-traversal-protection SEFA)) 
    ; 10. File system permissions allow reading outside intended directory
    (filesystem-permissions-allow-traversal SEFA)
    (located-at sensitive-file1_SEFA filesystem-path_SEFA)
    (data-stored-in-file sensitive-file-content1 sensitive-file1_SEFA)





    ;; ==== Added for CVE-2022-1471 =====
    ; 1. Application uses vulnerable SnakeYAML version (prior to 2.0, specifically 1.30-1.33)
    (has-dependency-on-snakeyaml SEFA snakeyaml-library_SEFA)
    (= (version  snakeyaml-library_SEFA) 1030003) ; versions 1.30+ to < 2.0
    ; 2. Java version vulnerable to JNDI injection (≤ 8u190 or ≤ 11.0.0)
    (implementated-by-java SEFA  java_SEFA)
    (= (version  java_SEFA) 8000006) 
    ; 3. Application accepts external YAML content from untrusted sources
    (has-external-yaml-endpoint SEFA yaml-endpoint_SEFA)
    (accepts-untrusted-yaml-input SEFA)
    ; 4. No input validation on YAML content
    ;(not (has-yaml-input-validation SEFA))
    ; 5. Uses default Constructor() instead of SafeConstructor
    (uses-default-constructor SEFA)
    ;(not (uses-safe-constructor SEFA)) 
    ; 6. No type restrictions during deserialization
    ;(not (has-yaml-type-restrictions SEFA))   
    ; 7. Sufficient privileges for code execution
    (has-sufficient-code-execution-privilege SEFA)    
    ; 8. No security controls preventing dangerous class instantiation
    ;(not (has-dangerous-class-instantiation-prevention SEFA))  
    ; 9. No sandbox restrictions
    ;(not (has-sandbox-restrictions SEFA))
    ; 10. Network connectivity for exfiltration
    (network-connectivity-available SEFA)

    (has-receive-endpoint SEFA yaml-endpoint_SEFA)

    
    ;; ==== Added for CVE-2025-24813 =====
    ;; 2. Tomcat Server's Default servlet has write permissions enabled - writes enabled for the default servlet (disabled by default)
    (tomcat-has-default-servlet SEFA default-servlet_SEFA)
    (tomcat-default-servlet-write-enabled SEFA default-servlet_SEFA)
    ;; 3. Partial PUT request support is enabled (enabled by default) - support for partial PUT (enabled by default) 
    (partial-put-request-enabled SEFA)
    ;; 4. Attacker has knowledge of public upload directories
    (has-public-directory SEFA public-directory_SEFA)
    (public-directory-exposed SEFA public-directory_SEFA)

    ;; distinguished preconditions for information disclosure and elevation of priviledge (RCE)
    ;; (or 
    ;;      (and ;;for information disclosure
    ;; 5. Security sensitive directories are sub-directories of public directories - a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads  
    (public-directory-has-sensitive-subdirectory public-directory_SEFA sensitive-directory_SEFA)
    (located-at sensitive-file2_SEFA sensitive-directory_SEFA)
    ;; 6. Attacker has knowledge of sensitive filenames - attacker knowledge of the names of security sensitive files being uploaded 
    (sensitive-filename-exposed SEFA sensitive-file2_SEFA)
    ;; 7. security sensitive files are uploaded via partial PUT requests - the security sensitive files also being uploaded via partial put
    (sensitive-file-partial-put-uploaded-enabled SEFA sensitive-file2_SEFA)
    ;;)
    ;; (and ;;for code excution
    ;; 8. For remote code execution: application uses Tomcat's file-based session persistence with default storage location -  application was using Tomcat's file based session persistence with the default storage location 
    (tomcat-file-based-session-persistence-enabled SEFA tomcat_SEFA) 
    (tomcat-default-session-storage-location SEFA tomcat_SEFA)
    ;;  ) )
    ;; 10. HTTP PUT method accessible to unauthenticated users
    (http-put-method-accessible SEFA)
        
    ;; 11. No WAF or security controls blocking malicious PUT requests
    ; (not (WAF-malicious-request-block SEFA))
    ; (not (security-controls-path-manipulation SEFA))
        
    ;; 12. Application processes filenames with internal dots without proper normalization
    ; (not (has-proper-path-normalization-for-filename SEFA))
    ; (not (has-proper-path-equivalence-validation-for-filename SEFA))

     (data-stored-in-file sensitive-file-content2 sensitive-file2_SEFA)
    
     (jsp-extension file-extension1) 
    ;(jspx-extension file-extension1)
     (tomcat-has-jsp-engine tomcat_SEFA jsp-engine_SEFA)
     (tomcat-jsp-engine-enabled SEFA tomcat_SEFA) 

     (has-tomcat-process SEFA tomcat-process_SEFA)

    ;; ==== Added for CVE-2023-2976 =====
 
     (guava-library guava-library_SEFA)
     (has-library SEFA guava-library_SEFA)
     (= (version guava-library_SEFA) 2003000000)
     (uses-filebackedoutputstream SEFA)
     (uses-uncontrolled-createtempfile SEFA)
     (java-tmpdir-set-to-world-writable SEFA)
     (has-os SEFA  host-os_SEFA)
     (world-readable-tempdir-permissions host-os_SEFA)
     (world-writable-tempdir-permissions host-os_SEFA)
     ;not (container-isolated SEFA)
     ;not(os-sandbox-isolated SEFA)
     ;not(uses-per-user-temp-directory SEFA)
     ;not(temp-directory-acl-protected SEFA)
     ;not(temp-directory-mount-restricted SEFA)
     (uses-predictable-temp-filenames SEFA)
     (writes-sensitive-data-to-temp SEFA)
     (temp-directory-under-surveillance temporary-directory_SEFA)


    ;; ==== Added for CVE-2024-38809 =====
     ;; 1. Application uses vulnerable Spring Framework spring-web module
     (has-framework SEFA spring-framework1)
     (spring-web-module spring-framework1)
    
     ;; 2. Application processes ETags from If-Match or If-None-Match headers
     (has-http-endpoint SEFA  http-endpoint_SEFA)
     (has-etag-handler SEFA etag-handler_SEFA)
     (processes-if-match-headers SEFA etag-handler_SEFA)
     (processes-if-none-match-headers SEFA etag-handler_SEFA)
     
     ;; 3. ETag parsing logic lacks proper validation
     ;not (has-etag-validation SEFA etag-handler_SEFA)
     ;not (has-etag-size-limits SEFA etag-handler_SEFA)
     ;not (has-etag-complexity-limits SEFA etag-handler_SEFA)
     
     ;; 4. Application exposes HTTP endpoints to untrusted users
     (publicly-accessible http-endpoint_SEFA)
     ;not (has-restrictive-access-controls http-endpoint_SEFA)
     
     ;; 5. No size limits on If-Match or If-None-Match headers
     ;not (has-header-size-limits SEFA http-endpoint_SEFA)
     ;not (has-framework-header-limits pring-framework1)
     ;not (has-servlet-container-limits SEFA)
     
     ;; 6. No rate limiting or request throttling
     ;not (has-http-rate-limiting SEFA http-endpoint_SEFA)
     ;not (has-request-throttling SEFA http-endpoint_SEFA)
     
     ;; 7. No custom input validation filters
     ;not (has-input-validation-filters SEFA)
     ;not (has-etag-validation-middleware SEFA)
     
     ;; 8. No WAF/IPS protection
     ;not (has-waf-protection SEFA)
     ;not (has-ips-protection SEFA)
     ;not (has-etag-header-detection-rules SEFA)
     
     ;; 9. Shared server resources without isolation
     (has-shared-resources SEFA)
     ;not (has-resource-isolation SEFA)
     
     ;; 10. Shared thread pool across endpoints
     (has-shared-thread-pool SEFA)
     ;not (has-endpoint-isolation SEFA)

    ;; ==== Added for CVE-2024-47072 =====
     ;1. Application uses vulnerable XStream version
     (has-library SEFA XStreamLibrary_SEFA)
     (xstream-library XStreamLibrary_SEFA)
     (= (version XStreamLibrary_SEFA) 1004010009) ;version <= 1.4.20
     
     ;2. Application configures XStream to use BinaryStreamDriver
     (has-binary-stream-driver SEFA binary-stream-driver_SEFA)
     (binary-stream-driver binary-stream-driver_SEFA)
     (xstream-uses-driver XStreamLibrary_SEFA binary-stream-driver_SEFA)
    
     ;3. Application accepts and processes attacker-controlled binary input streams 
     (accepts-binary-input SEFA API-endpoint_SEFA)
     (processes-untrusted-input SEFA API-endpoint_SEFA)
     
     ;4. Application lacks robust input validation or integrity checks
     ;not (api-endpoint-has-integrity-checks SEFA API-endpoint_SEFA)
     
     ;5. Application does not implement StackOverflowError exception handling
     ;not (has-stackoverflow-exception-handling SEFA)
     
     ;6. Application's runtime permits deeply nested structures without safeguards
     ;not (has-defense-in-depth-safeguards SEFA)
     ;not (has-recursive-structure-limits SEFA)
     
     ;7. Application lacks effective JVM stack size restrictions
     ;not (has-jvm-stack-size-restrictions SEFA)
     ;not (has-sufficient-stack-limits SEFA)
     
     ;8. Application lacks limits on input stream size or complexity
     ;not (has-input-stream-size-limits SEFA)
     ;not (has-structural-complexity-limits SEFA)
     
     ;9. Application lacks compensating security mechanisms
     ;not (has-sandboxing SEFA)
     ;not (has-deserialization-whitelist SEFA)
     ;not (has-waf-binary-filtering SEFA)

    ;; ==== Added for CVE-2023-33202 =====
    ; 1. vulnerable Bouncy Castle present: version < 1.73.0
    (has-library SEFA BCLibrary_SEFA)
    (bouncycastle-library BCLibrary_SEFA)
    (= (version BCLibrary_SEFA) 1007200011) ; version < 1.73.0 (encoding documented above)

    ; 2. application code invokes or forwards to PEMParser
    (uses-pemparser SEFA)

    ; 3. application exposes interface(s) that accept PEM/ASN.1 input
    (has-pem-endpoint SEFA pem-endpoint_SEFA)
    (accepts-pem-input SEFA pem-endpoint_SEFA)

    ; 4. parsing performed in-process on same JVM heap
    (parser-in-process SEFA)
    (parser-shares-jvm-heap SEFA)

    ; 5. no effective pre-validation/ASN.1 structural checks
    ;not (endpoint-has-content-type-enforcement SEFA pem-endpoint_SEFA)
    ;not (endpoint-has-asn1-sanity-checks SEFA pem-endpoint_SEFA)
    ;not (endpoint-rejects-suspicious-pem-patterns SEFA pem-endpoint_SEFA)

    ; 6. lacks request/resource controls (file-size, depth, timeouts, per-request caps)
    ;not (endpoint-has-file-size-limits SEFA pem-endpoint_SEFA)
    ;not (endpoint-has-asn1-depth-limits SEFA pem-endpoint_SEFA)
    ;not (endpoint-has-parser-timeouts SEFA pem-endpoint_SEFA)
    ;not (endpoint-has-per-request-memory-caps SEFA pem-endpoint_SEFA)

    ; 7. endpoints reachable with low/no privileges or insufficient rate-limiting
    (endpoint-reachable-to-attackers SEFA pem-endpoint_SEFA)
    ;not (endpoint-rate-limited SEFA pem-endpoint_SEFA)

    ; 8. JVM/container runtime lacks heap isolation / cgroup limits
    ;not (has-cgroup-memory-limit SEFA)
    ;not (has-pod-memory-limit SEFA)
    (single-jvm-hosting-critical-services SEFA)

    ; 9. no sandboxing or process isolation for untrusted parsing
    ;not (parsing-sandboxed SEFA)

    ; 10. error handling does not gracefully contain OutOfMemoryError
    ;not (has-circuit-breaker-for-oom SEFA)
    ;not (graceful-degradation-on-oom SEFA)

    ; 11. no upstream protections (WAF / upload policies / scanners)
    ;not (has-waf-protection SEFA)
    ;not (has-upload-policy-scanner SEFA pem-endpoint_SEFA)

    ;; ==== Added for CVE-2023-46589 =====
     (has-reverse-proxy SEFA reverse-proxy_SEFA)
     (forwards-requests reverse-proxy_SEFA tomcat_SEFA)
     
     ; 3. Application accepts HTTP/1.1 requests with Transfer-Encoding: chunked
     (accepts-chunked-encoding SEFA)
     (permits-trailer-headers reverse-proxy_SEFA)
     
     ; 4. Mismatched parsing between reverse proxy and Tomcat
     (mismatched-parsing reverse-proxy_SEFA tomcat_SEFA)
     (mismatched-trailer-handling reverse-proxy_SEFA tomcat_SEFA)
     (mismatched-header-limits reverse-proxy_SEFA tomcat_SEFA)
     
     ; 5. Reverse proxy forwards trailer header bytes without normalization
     ;not (normalizes-trailer-headers reverse-proxy_SEFA)
     ;not (rejects-oversized-trailers reverse-proxy_SEFA)
     ;not (truncates-oversized-trailers reverse-proxy_SEFA)
     
     ; 6. Backend connection allows reuse/keep-alive/pipelining
     (allows-connection-reuse reverse-proxy_SEFA tomcat_SEFA)
     (allows-keep-alive reverse-proxy_SEFA tomcat_SEFA)
     (allows-pipelining reverse-proxy_SEFA tomcat_SEFA)
     
     ; 7. Application exposes target endpoints reachable by attacker
     ; 8. Endpoints do not enforce strict per-request authentication
     ;not (strict-per-request-auth http-endpoint_SEFA)
     
     ; 9. Application lacks request smuggling detection mechanisms
     ;not (has-waf-smuggling-detection SEFA)
     ;not (has-ips-oversized-trailer-rules SEFA)
     ;not (rejects-malformed-trailers reverse-proxy_SEFA)
     ;not (has-request-canonicalization SEFA)

     
     (bond-to-user-account user1 sensitive-order1)
     (cacheable-resource cacheresource1)
     (has-cached-resource cacheresource1)
     (has-application-cache SEFA cache1_SEFA)


    ;;;(1).====================================END===================================;;;
  



    ;;;(2).================================USER STATE================================;;;
    ;; === for CVE-20224-12798 ===
    (user-visits-site user1 email-site)
    ;;(use-browser browser-chrome)
     
    ;;==== Added for CVE_2024_22243 AP 1&2 =====
    (user-has-valid-credentials-application user1 user1-password_SEFA SEFA)
    (is-default-browser browser-chrome)

    ;; ==== Added for CVE-2023-44487 =====
    (user-needs-to-use-application user1 SEFA)

    ;; ==== Added for CVE-2023-33202 =====
    (has-account user1 SEFA)
    
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
  (spoofing SEFA)))
  (:metric minimize (total-cost)))