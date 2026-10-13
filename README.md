Web Server Log Forensics: Investigating a Compromised WordPress Site

Tools: Log analysis of an Apache-style access log | Type: Academic lab Skills: Log analysis, proxy/abuse detection, user-agent analysis, incident reporting

Overview

I investigated a web server access log from a WordPress site to reconstruct what happened, who was involved, and what the site was being used for. Each question mirrors a Tier 1 SOC task: scope the timeline, identify the tooling, and separate malicious from benign traffic.

Data

Web server access log provided with course materials. The log is not included in this repo. Sensitive values found in the log are redacted below.

Findings
Question	Finding
Time range	19 Apr 2010 06:36:15 to 24 Apr 2010 18:51:54 (-0700)
Proxies involved?	Yes. Requests to proxy-checking endpoints (proxyjudge1.proxyfire.net/fastenv, www.wantsfly.com/prx2.php), plus CONNECT requests to 72.51.18.254:6677 and 92.62.43.77:6667
Proxy scanner	pxyscand/2.1, seen in the User-Agent of 3 CONNECT requests. The server answered them with HTTP 301, so it was not relaying traffic
Pages requested (GET)	/, /feed/, /login/, /signup/, /robots.txt, /wp-admin/, plus external URLs
POST targets	/signup/ (14 requests) and /wp-cron.php (18 requests)
Platform / version	WordPress 2.9.2, from the User-Agent string (18 requests)
Exposed credentials	A request to an external account-config URL carried a login and password in the query string in plaintext. (Values redacted.)
Bot identified	NaverBot/1.0 from 114.111.36.26
Analysis
The server was being used as a proxy test target. The CONNECT requests, the proxy-judge URLs, and the pxyscand user agent together show an automated proxy scanner probing whether the host could relay traffic. The 301 responses show the probes did not succeed. Port 6667 is the standard IRC port, which is a common destination for botnet and chat-based tooling.
The signup page was a likely abuse point. POST requests to /signup/ are consistent with automated account creation.
WordPress 2.9.2 is long out of date, which means known unpatched vulnerabilities.
Credentials in a URL query string is a security failure by itself. Query strings are logged by servers and proxies in plaintext.
NaverBot is a known search-engine crawler, so it is most likely benign. In a real investigation I would confirm with a reverse DNS lookup on the IP, since user agents can be spoofed.
Recommended Actions
Update WordPress and plugins, and remove unused accounts.
Block the proxy-scanner user agent and offending IPs; rate-limit /signup/.
Add CAPTCHA or email verification to registration.
Reset any exposed credentials and never pass them in URLs.
Forward web logs to a SIEM with alerts for CONNECT requests and scanner user agents.
Method

Reviewed the 365-line access log by searching for key fields. Example commands:

grep -c pxyscand "web server.log"            # scanner user-agent hits
grep CONNECT "web server.log"                 # proxy CONNECT attempts
grep '"POST' "web server.log" | awk '{print $7}' | sort | uniq -c   # POST targets
grep -i naverbot "web server.log"             # bot identification
What I Learned
User-agent strings reveal tooling quickly, but they can be spoofed.
Even a small log can tell a complete story of what an attacker was trying to do.
