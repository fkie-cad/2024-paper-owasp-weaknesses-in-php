# Detail Discussion and Rating of OWASP Top 10 2021 Classes

We consolidate three weakness properties that can hinder the detection of vulnerabilities:

**(B) = Business Logic**

**(D) = Insecure System Design**

**(R) = Runtime-Behavior or -Context**

Now, we independently rate the degree to which a property can negatively affect the detectability of an OWASP class on a scale of four values:

$1$: *A property (almost) never affects the OWASP class.*   

$2\over3$: *A property affects the class in some, but not the majority of cases.*  

$1\over3$: *A property affects a class in the majority, but not all cases.*  

$0$: *A property (almost) always affects the OWASP class.*  

We discuss about the results to determine a final score for each property and class by majority voting.

### A01) Broken Access Control (B: $1\over3$ R: $1\over3$ D: $1\over3$)

Broken access control describes a violation of a predefined access control, which can lead to unauthorized access to sensitive data [[OWASP-A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)].
Causes for such a breach can be an insecure specification of access authorizations and an incorrect enforcement of access control [[CWE-284](https://cwe.mitre.org/data/definitions/284.html)].
Both causes are problems of insecure system design (*No Insecure System Design* = $1\over3$).
Detection therefore requires knowledge of the application's access control mechanisms and their enforcement.
It must also be known which resources are sensitive and need to be protected [[CWE-922](https://cwe.mitre.org/data/definitions/922.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html)].
This knowledge often cannot be derived directly from the code (*No Business Logic* = $1\over3$). 
In addition, session information such as the role and access rights of the current user are often only available at runtime (*No Runtime-Behavior or -Context* = $1\over3$) . 
However, using taint analysis semgrep could find user-controlled variables that are passed to a sensitive file operation management function and thus detect e.g. [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
Also, an insecure configuration of access control operations could be detected e.g. by looking for known insecure cookie configurations, which can lead to [CWE-352](https://cwe.mitre.org/data/definitions/352.html).

### A02) Cryptographic Failures (B: $1\over3$ R: $1$ D: $2\over3$)

Cryptographic failures result from improper or missing use of cryptography. 
This can result in data breaches or the leak of sensitive information [[OWASP-A02](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)].
Detecting A02 weaknesses poses the same challenges observed in A01, as it requires explicit knowledge of which data must be encrypted and whether its protection is implemented correctly [[CWE-523](https://cwe.mitre.org/data/definitions/523.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html)].
Thus they may not manifest within the code itself and can be a problem of higher-level scopes. 
However, there are some instances, which can be detected by Semgrep using text-based analysis:

By checking for function names, Semgrep can detect the usage of insecure and deprecated cryptographic algorithms (*No Insecure System Design* = $2\over3$).
Furthermore, Semgrep could detect known misconfigurations of used cryptographic algorithms, e.g., weak key size or to few hashing rounds, as they are introduced by specific implementation errors (*No Business Logic* = $1\over3$) [[CWE-327](https://cwe.mitre.org/data/definitions/327.html)].
Such misconfigurations are not bound to runtime, as they must be specified before execution (*No Runtime-Behavior or -Context* = $1$).

### A03) Injection (B: $2\over3$ R: $1$ D: $1$)

Injection vulnerabilities occur when untrusted data is passed unsanitized to a sensitive function, allowing attackers to inject malicious data. 
Common injection vulnerabilities include command injection, Cross-Site Scripting, and SQL injection, which are all caused by insufficient or improper handling of user-controlled input [[OWASP-A03](https://owasp.org/Top10/A03_2021-Injection/)].
Thus, injection vulnerabilities typically manifest themselves in code and are independent of system architecture and business logic (*No Insecure System Design* = $1$). 
While it may require manual review to identify vulnerable sections in an application, analysts could search for known critical functions, e.g., file includes or database queries. 
Then, Semgrep's taint analysis can trace user-modifiable variables to these vulnerable functions and detect most injection vulnerabilities (*No Business Logic* = $2\over3$).
Since data flows must be established before execution, the detection of injection vulnerabilities is not reliant on runtime contexts (*No Runtime-Behavior or -Context* = $1$).

### A04) Insecure Design (B: $1\over3$ R: $2\over3$ D: $0$)

Insecure design vulnerabilities are caused by general design flaws rather than specific coding errors and should therefore be distinguished from insecure implementation vulnerabilities [[OWASP-A04](https://owasp.org/Top10/A04_2021-Insecure_Design/)].

The detection of A04 weaknesses poses the same challenges seen in A01 and A02:
It requires additional knowledge about the business logic and specifications regarding access control and privilege assignment (*No Insecure System Design* = $0$) [[CWE-266](https://cwe.mitre.org/data/definitions/266.html),[CWE-312](https://cwe.mitre.org/data/definitions/312.html)].
Knowing which data is sensitive and how it needs to be protected often cannot be inferred from the code itself, which further hampers the detection of A04 vulnerabilities, such as [CWE-209](https://cwe.mitre.org/data/definitions/209.html) (*No Business Logic* = $1\over3$).
Detecting other weaknesses like [CWE-841](https://cwe.mitre.org/data/definitions/841.html) can also require runtime context or additional knowledge about restrictions based on the current user's privileges (*No Runtime-Behavior or -Context* = $2\over3$).

### A05) Security Misconfiguration (B: $1\over3$ R: $2\over3$ D: $1$)

Security misconfiguration weaknesses are caused by improper or incomplete configuration of an application or its components [[OWASP-A05](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)].
We discussed several examples and limitations of the detection of this in A01 and A02:
First, knowing which misconfiguration to scan for often requires knowledge of the used packages or libraries and an up-to-date list of known misconfigurations.
Second, we require knowledge about what information is sensitive and needs to be protected (*No Business Logic* = $1\over3$). 
Most CWEs mapped to this class do not require specific runtime context, as their configuration is done before runtime, e.g., configurations of cookie storage (cf. [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html), [CWE-614](https://cwe.mitre.org/data/definitions/614.html), and cross-domain policies. 
However, if a setting can be changed during runtime, discovering the resulting vulnerability might be difficult (*No Runtime-Behavior or -Context* = $2\over3$).
Furthermore, some configurations happen outside the scope given in the source code. 
Settings of CI/CD pipelines or used components like external authentication services might be configured on the services website or other sources, which are not visible in the code itself.
Since weaknesses of A05 are caused by improper or incomplete configuration of an application or its components, they result in insecure systems but are not caused by inherent insecure system design (*No Insecure System Design* = $1$)

### A06) Vulnerable and Outdated Components (B: $1\over3$ R: $2\over3$ D: $1$)

Vulnerable and outdated components refer to using third-party libraries, frameworks, components, or software versions that are no longer maintained, supported, or known to be vulnerable [[OWASP-A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)].
Similar to A05, most vulnerabilities of this class do not depend on runtime behavior, as the usage of a vulnerable component or its functions can typically be derived from the code itself.
However, Semgrep cannot detect compatibility issues resulting in errors or crashes during runtime (*No Runtime-Behavior or -Context* = $2\over3$).
While the exploitability of A06 vulnerabilities depends on a package's privileges and used functionalities, which can be varied by the implemented business logic, their obsolete or vulnerable nature remains. 
Yet, unlike in A03, where vulnerabilities often involve 'built-in' functions, the detection of vulnerable code in used packages may require additional information about them, as they can implement custom functionality (*No Business Logic* = $1\over3$).
Using these components or functions results in insecure systems but is not caused by high-level decisions in the system's design (*No Insecure System Design* = $1$).

### A07) Identification and Authentication Failures (B: $1\over3$ R: $1\over3$ D: $1\over3$)

Identification and authentication failures occur when an application fails to authenticate users properly, resulting in insufficient protection of sensitive data or functionality [[OWASP-A07](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)].
Since this class of weaknesses is closely related to A02 and A04, one can observe the same challenges in vulnerability detection:
CWEs mapped to A07 often require additional information about the implemented business logic, such as authentication policies and how they are implemented, and the systems architecture, such as insecure password recovery mechanism (*No Business Logic* = $1\over3$) [[CWE-307](https://cwe.mitre.org/data/definitions/307.html),[CWE-290](https://cwe.mitre.org/data/definitions/290.html)].
Furthermore, correct enforcement of restrictions like a limited number of invalid login tries or specific password requirements are difficult to detect without executing the application (*No Runtime-Behavior or -Context* = $1\over3$). 
Other vulnerabilities occur due to insecure system design, such as [CWE-640](https://cwe.mitre.org/data/definitions/640.html) or [CWE-521](https://cwe.mitre.org/data/definitions/521.html) (*No Insecure System Design* = $1\over3$).

### A08) Software and Data Integrity Failures (B: $1\over3$ R: $2\over3$ D: $1\over3$)

Software and data integrity failures emerge when untrusted actors, such as users and packages, are able to manage (critical) information without adequate protection mechanisms.
They may lead to data manipulation, corruption, and loss of complete system integrity [[OWASP-A08](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)].
Similar to A06, Semgrep can find known vulnerable software if its usage is evident within the code. 
Furthermore, [CWE-345](https://cwe.mitre.org/data/definitions/345.html) and [CWE-829](https://cwe.mitre.org/data/definitions/829.html), both describing the fundamental issues of Remote File Inclusion, can be detected by Semgrep.
However, it is challenging to identify which source should be able to manage which data without knowledge of, e.g., the access control matrix (*No Business Logic* = $1\over3$; *No Runtime-Behavior or -Context* = $2\over3$).
Additionally, many vulnerabilities from this class result from high-level implementation failures. 
For example, insecure configurations of CI/CD pipelines might allow for unauthorized access by used packages or third-party libraries. 
This can lead to sensitive data being manipulated or leaked to the source of the used component. 
As configurations of external services and functionalities are generally not done in the application's source code, Semgrep cannot find these weaknesses. 
In addition, Semgrep does not know which package is allowed to process which data. 
Overall, Semgrep is therefore unable to detect vulnerabilities resulting from dependencies on untrusted, potentially malicious sources that are not identified as such (*No Insecure System Design* = $1\over3$). 

### A09) Security Logging and Monitoring Failures (B: $0$ R: $1\over3$ D: $1$)

Logging provides introspection and traceability of application execution.
Improper or missing logging and monitoring mechanisms of e.g. authentication flows can result in undetectable security violations [[OWASP-A09](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)].
Which actions are security-related and what information is required?
It is hard for Semgrep to identify missing logging ([CWE-778](https://cwe.mitre.org/data/definitions/778.html)) or improper log granularity ([CWE-223](https://cwe.mitre.org/data/definitions/223.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html)) in code without considering application-specific business logic (*No Business Logic* = $0$).
An intertwined issue is that answers to the previous questions depend on runtime assumptions for specific attack vectors, e.g., the involved data flows (*No Runtime-Behavior or -Context* = $1\over3$).
Yet, A09 describes implementation errors and is system design independent (*No Insecure System Design* = $1$).
While we estimate that Semgrep cannot easily find most A09 issues, we raise an exception: [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
It describes improper sanitization of user-controlled input in log files.
This is a taint-style injection with known sources.
If sinks are defined, this subtype appears detectable.
However, we claim that the scoring impact of this issue is not sufficient because all other A09 issues require application-specific business logic and this vulnerability can also be mapped to class A03) Injection in the scope of logging.

### A10) Server-Side Request Forgery (B: $2\over3$ R: $1$ D: $1$)

Server-Side Request Forgery issues occur when servers are tricked into requesting arbitrary resources through unsanitized input [[OWASP-A10](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)].
As injection variant, it is detectable via taint analysis.
It inherits the A03 estimations (*No Runtime-Behavior or -Context* = $1$; *No Insecure System Design* = $1$) with similar limitations in business logic:
Without application-specific rules, Semgrep cannot distinguish allowed from forbidden~resources (*No Business Logic* = $2\over3$).
