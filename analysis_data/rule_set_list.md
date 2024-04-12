# Rule Set List

The table below provides an overview of all 57 publicly available rules used in our analysis, which we obtained from [Semgrep's official PHP registry](https://github.com/semgrep/semgrep-rules/tree/develop/php). The rule set commit hash was `e32bb84`. We also provide a brief description of what they aim to detect.

| Class | Rule ID | Description |
|-------|---------|-------------|
| A01 | phpinfo-use | Detects the usage of the 'phpinfo' function, as it may reveal sensitive information about the application's environment. |
| A01 | redirect-to-request-uri | Detects redirects to the current request URL, as they may redirect to another domain, if the current path starts with two slashes. |
| A01 | unlink-use | Detects the usage of user input when deleting files with 'unlink()'. |
| A01 | laravel-blade-form-missing-csrf | Detects a form executing a state-changing HTTP method to a route definition without a Laravel CSRF decorator or explicit CSRF token implementation. This can lead to CSRF vulnerabilities. |
| A01 | laravel-cookie-null-domain | Detects a configuration file where the 'domain' attribute of a cookie is set to null, which could lead to the exposure of them to other web services. |
| A01 | laravel-cookie-same-site | Detects a configuration file where the 'same_site' attribute of a cookie is not set to 'lax' or 'strict', which may expose them and risk CSRF vulnerabilities. |
| A01 | symfony-csrf-protection-disabled | Detects disabled CSRF protection. |
| A01 | symfony-non-literal-redirect | Detects redirect based on user input leading to unvalidated redirect security vulnerabilities. |
| A01 | wp-ajax-no-auth-and-auth-hooks-audit | Detects the usage of custom AJAX hooks in used plugins which should be validated. |
| A01 | wp-authorisation-checks-audit | Detects WordPress functions for user authorisation in WordPress plugins, whose implementation should be validated. |
| A01 | wp-file-download-audit | Detects non-constant file download in a used WordPress package. This can lead to LFI or RFI. |
| A02 | weak-crypto | Detects usage of weak or deprecated hash functions. |
| A02 | curl-ssl-verifypeer-off | Detects disabled SSL peer verification. | 
| A02 | ftp-use | Detects the usage of FTP, as it allows for unencrypted file transfers. |
| A02 | openssl-decrypt-validate | The function 'openssl_decrypt' returns either a string of the data on success or 'false' on failure. This rule aims to detect whether the failure case is not handled, as this could lead to undefined behavior in an application. |
| A02 | openssl-cbc-static-iv | Detects static OpenSSL initialization vector used with AES in CBC mode, as this allows chosen-plaintext attacks against encrypted data. |
| A02 | md5-used-as-password | Detects the usage of 'md5()' output as a password hash. |
| A03 | echoed-request | Detects unsanitized echoed user input, as this could lead to cross-site scripting vulnerabilities. |
| A03 | tainted-object-instantiation | Detects object instantiation based on user input, as this could lead to remote code execution. |
| A03 | tainted-sql-string | Aims to detect user data flows into manually-constructed SQL strings. This could lead to SQL injection without prepared statements or proper variable binding. |
| A03 | assert-use | Detects non-literal assert uses with user-modifiable variables, as this is equivalent to eval'ing. _Note: Matches different pattern than 'assert-use-audit'._ |
| A03 | backticks-use | Detects the usage of backticks as they can lead to command injection vulnerabilities |
| A03 | eval-use | Detects evaluating non-constant commands. This can lead to command injection. |
| A03 | exec-use | Detects executing non-constant commands. This can lead to command injection. |
| A03 | file-inclusion | Detects non-constant file inclusion. This can lead to LFI or RFI. |
| A03 | mb-ereg-replace-eval | Detects 'mb_ereg_replace' usage with user input in the options, as this can lead to arbitrary code execution. |
| A03 | non-literal-header | Detects user input when setting headers with 'header()', as this can lead to injection vulnerabilities. |
| A03 | preg-replace-eval | Deprecated Rule which remains in the registry - see [here](https://github.com/returntocorp/semgrep-rules/issues/2506). |
| A03 | assert-use-audit | Detects non-literal assert uses with user-modifiable variables, as this is equivalent to eval'ing. _Note: Matches different pattern than 'assert-use'._ |
| A03 | doctrine-dbal-dangerous-query | Detects string concatenation with a non-literal variable in a Doctrine DBAL query method. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. |
| A03 | doctrine-orm-dangerous-query | Detects string concatenation with a non-literal variable in a Doctrine QueryBuilder method. This could lead to SQL injection if the variable is user-controlled and not properly sanitized. |
| A03 | laravel-api-route-sql-injection | Detects string concatenation or unsafe interpolation based on a Laravel Route, which is passed to a database query. This can lead to SQl injection. |
| A03 | laravel-sql-injection | Detects a SQL query based on user input. This could lead to SQL injection. |
| A03 | laravel-unsafe-validator | Detects a request argument passed to an 'ignore()' definition in a Rule constraint. This can lead to SQL injection. |
| A03 | wp-code-execution-audit | Detects non-constant use of code execution functions in WordPress plugins which could lead to injection vulnerabilities. |
| A03 | wp-command-execution-audit | Detects non-constant use of command execution functions in WordPress plugins which could lead to command injection vulnerabilities. |
| A03 | wp-sql-injection-audit | Detects a SQL query based on user input in a used WordPress package. This could lead to SQL injection. |
| A03 | wp-php-object-injection-audit | Detects usage of 'unserialize()' with user input in an used WordPress package. This this can lead to object injection. |
| A05 | laravel-active-debug-code | Detects if the 'APP_DEBUG' environment variable is set to true, which risks exposing sensitive in the production environment. |
| A05 | laravel-cookie-http-only | Detects if the 'http_only' setting is not set to true which could lead to XSS vulnerabilities. |
| A05 | laravel-cookie-long-timeout | Detects a configuration file where the 'lifetime' attribute of a cookie is over 30 minutes. |
| A05 | laravel-cookie-secure-set | Detects a configuration file where the 'secure' attribute of a cookie is not set to true, which allows transmitting them over unencrypted channels. This risks cookies being stolen through man in the middle attacks. |
| A05 | wp-csrf-audit | Detects redundant validation of a 'ajax_referer' check in WordPress plugins, which could lead to CSRF vulnerabilities. |
| A05 | wp-open-redirect-audit | Detects non-constant redirect in a used WordPress plugin, which can lead to Open Redirect vulnerabilities. |
| A07 | ldap-bind-without-password | Detects anonymous LDAP bind. This permits anonymous users to execute LDAP statements. |
| A07 | php-permissive-cors | Detects if the Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions. |
| A07 | symfony-permissive-cors | Detects if the Access-Control-Allow-Origin response header is set to "*". This will disable CORS Same Origin Policy restrictions. |
| A08 | extract-user-data | Detects 'extract' usage on user-controllable data, as this can lead to existing variables being overwritten. |
| A08 | unserialize-use | Detects usage of 'unserialize()' with user input in the pattern, as this can lead to arbitrary code execution. |
| A08 | laravel-dangerous-model-construction | Detects if '\$guarded' is set to an empty array, which allows mass assignment to every property in a Laravel model. |
| A08 | wp-file-inclusion-audit | Detects non-constant file inclusion in a used WordPress package. This can lead to LFI or RFI. |
| A08 | wp-file-manipulation-audit | Detects the usage of user input when deleting files with 'unlink()' in a WordPress plugin. |
| A10 | php-ssrf | Detects if the web server receives a URL or similar request from an upstream component (user-modifiable data) and retrieves the contents of this URL. |
| A10 | tainted-filename | Detects file operations where the file name is based on user input, as this risks server-side request forgery. |
| A10 | tainted-url-host | Detects user data which flows into the host portion of manually-constructed URLs leading to possible SSRF vulnerabilities. |
|- | mcrypt-use | Detects usage of deprecated 'mcrypt' functions. |
|- | md5-loose-equality | Detects unsafe comparisons involving md5 values. They should be strict ('===' not '==') to avoid type juggling issues. |