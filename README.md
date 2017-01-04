# autoprox
This is a tool to troubleshoot usage of Proxy Auto Configuration (PAC) or Web Proxy Autodiscovery Protocol (WPAD) files.
Help for AUTOPROX.EXE

Version : 2.42

Written by pierrelc@microsoft.com

Usage : AUTOPROX -a  (calling DetectAutoProxyUrl and saving wpad.dat file in temporary file if success)

Usage : AUTOPROX -n  (calling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DNS_A only and saving wpad.dat file in temporary file if success)
Usage : AUTOPROX  [-o] [-d] [-v] [-u:url] [-p:Path to autoproxy file] [-i:IP address]    

-o: calls InternetInitializeAutoProxyDll with helper functions implemented in AUTOPROX   

-i:IP Address: calls InternetInitializeAutoProxyDll with helper functions implemented in AUTOPROX and using provided IP Address 

-v: verbose output for helper functions

For debugging:  -d plus HKEY_CURRENT_USER\Software\Microsoft\Windows Script\Settings\JITDebug=1AUTOPROX 
-u:url: calling DetectAutoProxyUrl and using autoproxy file to find the proxy for the urlAUTOPROX -u:url 

-p:path: using the autoproxy file/url from the path to find proxy for the url

Example: autoprox http://www.microsoft.com -> calling DetectAutoProxyUrl and using WPAD if found

Example: autoprox -o -u:http://www.microsoft.com -p:c:\inetpub\wwwroot\wpad.dat

Example: autoprox -u:http://www.microsoft.com -p:http://proxy/wpad.dat

Example: autoprox -d -u:http://www.microsoft.com -p:http://proxy/wpad.dat


APIs used: URLDownloadToFileA, ReadAutoProxyDetectType, DetectAutoProxyUrl, getaddrinfo, InternetInitializeAutoProxyDll,
InternetGetProxyInfo 
