// autoprox.cpp : Defines the entry point for the console application.
//
/*Version history */
/*1.01 Added call to WSAStartup*/

#include "stdafx.h"


// NOTE: When building, link explicitly with the following libraries:
//                               wininet.lib
//                               ws2_32.lib
//                               urlmon.lib

#define WIN32_LEAN_AND_MEAN	1

#include <windows.h>
#include "wininet.h"
#include <urlmon.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

void ErrorPrint();
void reportFuncErr(char* funcName);
TCHAR * LoopStringUpper(TCHAR *arg1, TCHAR *arg2);

TCHAR IpAddress[16];
char myIpAddress[16];
BOOL bUseIpAddress = FALSE;
BOOL bVerboseHelpers = FALSE;
DWORD QueryWellKnownDnsName(__out PSTR *ppwszAutoProxyUrl);


//////////////////////////////////////////////////////////////////////
// Methode : LoopStringUpper
// Resume : Like strstr but non case sensitive 
//			Return a pointer to the first occurrence of a search string in a string.
// In : *arg1 = string 
//		*arg2 = search string
// Out : pointer to the first occurrence
// Extract from http://msdn2.microsoft.com/en-us/library/z9da80kz(VS.80).aspx
//////////////////////////////////////////////////////////////////////
TCHAR * LoopStringUpper(TCHAR *arg1, TCHAR *arg2)
{
	TCHAR buff1[MAX_PATH];
	TCHAR buff2[MAX_PATH];

	wcscpy_s(buff1, arg1);
	wcscpy_s(buff2, arg2);

	_wcsupr_s(buff1);
	_wcsupr_s(buff2);

	return wcsstr(buff1, buff2);

}

/* ==================================================================
                            HELPER FUNCTIONS
   ================================================================== */

/////////////////////////////////////////////////////////////////////
//  ResolveHostName                               (a helper function)
/////////////////////////////////////////////////////////////////////
DWORD __stdcall ResolveHostName( LPSTR   lpszHostName,
                                 LPSTR   lpszIPAddress,
                                 LPDWORD lpdwIPAddressSize )
{
  DWORD dwIPAddressSize;
  addrinfo Hints;
  LPADDRINFO lpAddrInfo;
  LPADDRINFO IPv4Only;
  DWORD error;
  if (bVerboseHelpers)
  {
	  printf("ResolveHostByName called with lpszHostName: %s\r\n", lpszHostName);
  }
  // Figure out first whether to resolve a name or an address literal.
  // If getaddrinfo( ) with the AI_NUMERICHOST flag succeeds, then
  // lpszHostName points to a string representation of an IPv4 or IPv6 
  // address. Otherwise, getaddrinfo( ) should return EAI_NONAME.
  ZeroMemory( &Hints, sizeof(addrinfo) );
  Hints.ai_flags    = AI_NUMERICHOST;  // Only check for address literals.
  Hints.ai_family   = PF_UNSPEC;       // Accept any protocol family.
  Hints.ai_socktype = SOCK_STREAM;     // Constrain results to stream socket.
  Hints.ai_protocol = IPPROTO_TCP;     // Constrain results to TCP.


  error = getaddrinfo( lpszHostName, NULL, &Hints, &lpAddrInfo );
  if( error != EAI_NONAME )
  {
    if( error != 0 )
    {
		printf("getaddrinfo failed with error %d\n", error);
      error = ( error == EAI_MEMORY ) ?
           ERROR_NOT_ENOUGH_MEMORY : ERROR_INTERNET_NAME_NOT_RESOLVED;
      goto quit;
    }
    freeaddrinfo( lpAddrInfo );

    // An IP address (either v4 or v6) was passed in, so if there is 
    // room in the lpszIPAddress buffer, copy it back out and return.
    dwIPAddressSize = lstrlenA( lpszHostName );

    if( ( *lpdwIPAddressSize < dwIPAddressSize ) ||
        ( lpszIPAddress == NULL ) )
    {
      *lpdwIPAddressSize = dwIPAddressSize + 1;
      error = ERROR_INSUFFICIENT_BUFFER;
      goto quit;
    }
    lstrcpyA( lpszIPAddress, lpszHostName );
    goto quit;
  }

  // Call getaddrinfo( ) again, this time with no flag set.
  Hints.ai_flags = 0;
  error = getaddrinfo( lpszHostName, NULL, &Hints, &lpAddrInfo );
  if( error != 0 )
  {
    error = ( error == EAI_MEMORY ) ?
           ERROR_NOT_ENOUGH_MEMORY : ERROR_INTERNET_NAME_NOT_RESOLVED;
    goto quit;
  }

  // Convert the IP address in addrinfo into a string.
  // (the following code only handles IPv4 addresses)
  IPv4Only = lpAddrInfo;
  while( IPv4Only->ai_family != AF_INET )
  {
    IPv4Only = IPv4Only->ai_next;
    if( IPv4Only == NULL )
    {
      error = ERROR_INTERNET_NAME_NOT_RESOLVED;
      goto quit;
    }
  }
  error = getnameinfo( IPv4Only->ai_addr, 
                       IPv4Only->ai_addrlen, 
                       lpszIPAddress,
                       *lpdwIPAddressSize, 
                       NULL, 0, 
                       NI_NUMERICHOST );
  if( error != 0 )
    error = ERROR_INTERNET_NAME_NOT_RESOLVED;

quit:

  if (error == ERROR_INTERNET_NAME_NOT_RESOLVED)
  {
	  printf("ResolveHostByName returning ERROR_INTERNET_NAME_NOT_RESOLVED\r\n");
  }
  else if (!error)
  {
	  if (*lpszIPAddress)
	  {
		  if (bVerboseHelpers)
		  {
			  printf("ResolveHostByName returning lpszIPAddress: %s\r\n", lpszIPAddress);
		  }
	  }
  }
  return( error );
}


/////////////////////////////////////////////////////////////////////
//  IsResolvable                                  (a helper function)
/////////////////////////////////////////////////////////////////////
BOOL __stdcall IsResolvable( LPSTR lpszHost )
{
  char szDummy[255];
  DWORD dwDummySize = sizeof(szDummy) - 1;
  printf("IsResolvable called with lpszHost: %s\r\n",lpszHost);
  if( ResolveHostName( lpszHost, szDummy, &dwDummySize ) )
  {
	  if (bVerboseHelpers)
	  {
		  printf("IsResolvable returning FALSE\r\n");
	  }
	return(FALSE);
	  
  }
  if (bVerboseHelpers)
  {
	  printf("IsResolvable returning TRUE\r\n");
  }
  return TRUE;
}

//Rev1.7
/////////////////////////////////////////////////////////////////////
//  IsResolvable                                  (a helper function)
/////////////////////////////////////////////////////////////////////
BOOL __stdcall IsResolvableEx( LPSTR lpszHost )
{
  char szDummy[255];
  DWORD dwDummySize = sizeof(szDummy) - 1;
  if (bVerboseHelpers)
  {
	  printf("IsResolvableEx called with lpszHost: %s\r\n", lpszHost);
  }
  if( ResolveHostName( lpszHost, szDummy, &dwDummySize ) )
  {
		if (bVerboseHelpers)
		{
			printf("IsResolvableEx returning FALSE\r\n");
		}
		return( FALSE );
  }
  if (bVerboseHelpers)
  {
	  printf("IsResolvableEx returning TRUE\r\n");
  }
  return TRUE;
}
/////////////////////////////////////////////////////////////////////
//  GetIPAddress                                  (a helper function)
/////////////////////////////////////////////////////////////////////
DWORD __stdcall GetIPAddress( LPSTR   lpszIPAddress,
                              LPDWORD lpdwIPAddressSize )
{
  char szHostBuffer[255];
  printf("GetIPAddress called\r\n");
  if (bUseIpAddress)
  {
	printf("Returning IP Address given as parameter: %s\r\n", myIpAddress);
	strcpy_s(lpszIPAddress, 16, myIpAddress);
	*lpdwIPAddressSize = strlen(myIpAddress);
	return (ERROR_SUCCESS);
  }

  if( gethostname( szHostBuffer, sizeof(szHostBuffer) - 1 ) != ERROR_SUCCESS )
  {
	printf("GetIPAddress returning ERROR_INTERNET_INTERNAL_ERROR\r\n");
	return( ERROR_INTERNET_INTERNAL_ERROR );
  }
  DWORD dwReturn= ResolveHostName( szHostBuffer, 
                           lpszIPAddress, 
                           lpdwIPAddressSize ) ;
  if (!dwReturn)
  {
	  if (bVerboseHelpers)
	  {
		  printf("GetIPAddress returning lpszIPAddress: %s\r\n", lpszIPAddress);
	  }
  }
  else
  {
	  if (bVerboseHelpers)
	  {
		  printf("GetIPAddress returning error: %d\r\n", dwReturn);
	  }
  }
  return dwReturn;
}

//version 1.07
//Adding support for GetIPAddressEx
/////////////////////////////////////////////////////////////////////
//  GetIPAddress                                  (a helper function)
/////////////////////////////////////////////////////////////////////
DWORD __stdcall GetIPAddressEx( LPSTR   lpszIPAddress,
                              LPDWORD lpdwIPAddressSize )
{
  char szHostBuffer[255];
  if (bVerboseHelpers)
  {
	  printf("GetIPAddressEx called\r\n");
  }
  if (bUseIpAddress)
  {
	printf("Returning IP Address given as parameter: %s\r\n", myIpAddress);
	strcpy_s(lpszIPAddress, 16, myIpAddress);
	*lpdwIPAddressSize = strlen(myIpAddress);
	return (ERROR_SUCCESS);
  }

  if( gethostname( szHostBuffer, sizeof(szHostBuffer) - 1 ) != ERROR_SUCCESS )
  {
	printf("GetIPAddressEx returning ERROR_INTERNET_INTERNAL_ERROR\r\n");
    return( ERROR_INTERNET_INTERNAL_ERROR );
  }

  DWORD dwReturn= ResolveHostName( szHostBuffer, 
                           lpszIPAddress, 
                           lpdwIPAddressSize ) ;
  if (!dwReturn)
  {
	  if (bVerboseHelpers)
	  {
		  printf("GetIPAddressEx returning lpszIPAddress: %s\r\n", lpszIPAddress);
	  }
  }
  else
  {
	  if (bVerboseHelpers)
	  {
		  printf("GetIPAddressEx returning error: %d\r\n", dwReturn);
	  }
  }
  return dwReturn;
}

/////////////////////////////////////////////////////////////////////
//  IsInNet                                       (a helper function)
/////////////////////////////////////////////////////////////////////
BOOL __stdcall IsInNet( LPSTR lpszIPAddress, 
                        LPSTR lpszDest, 
                        LPSTR lpszMask )
{
  DWORD dwDest;
  DWORD dwIpAddr;
  DWORD dwMask;
  if (bVerboseHelpers)
  {
	  printf("IsInNet called with ");
	  if ((lpszIPAddress) && (*lpszIPAddress))
		  printf("lpszIPAddress: %s", lpszIPAddress);
	  if ((lpszIPAddress) && (*lpszDest))
		  printf(" lpszDest %s", lpszDest);
	  if ((lpszMask) && (*lpszMask))
		  printf(" lpszMask %s", lpszMask);
	  printf("\r\n");
  }
  dwIpAddr = inet_addr( lpszIPAddress );
  dwDest   = inet_addr( lpszDest );
  dwMask   = inet_addr( lpszMask );

  if( ( dwDest == INADDR_NONE ) ||
      ( dwIpAddr == INADDR_NONE ) ||
      ( ( dwIpAddr & dwMask ) != dwDest ) )
  {
	  if (bVerboseHelpers)
	  {
		  printf("IsInNet returning FALSE\r\n");
	  }
    return( FALSE );
  }
  if (bVerboseHelpers)
  {
	  printf("IsInNet returning TRUE\r\n");
  }
  return( TRUE );
}



void GetHost(char *pwszUrl, char *pwszHost)
{
	URL_COMPONENTSA URLparts;

	URLparts.dwStructSize = sizeof( URLparts );

	// The following elements determine which components are displayed
	URLparts.dwSchemeLength    = 1;
	URLparts.dwHostNameLength  = 1;
	URLparts.dwUserNameLength  = 1;
	URLparts.dwPasswordLength  = 1;
	URLparts.dwUrlPathLength   = 1;
	URLparts.dwExtraInfoLength = 1;

	URLparts.lpszScheme     = NULL;
	URLparts.lpszHostName   = NULL;
	URLparts.lpszUserName   = NULL;
	URLparts.lpszPassword   = NULL;
	URLparts.lpszUrlPath    = NULL;
	URLparts.lpszExtraInfo  = NULL;

	if( !InternetCrackUrlA((const char *)pwszUrl, strlen( pwszUrl ), 0, &URLparts ) )
	{
	   reportFuncErr( "InternetCrackUrl");
	}
	if (URLparts.lpszHostName)
	{
		lstrcpynA(pwszHost,URLparts.lpszHostName,URLparts.dwHostNameLength+1);
	}
	return;
}

/*16/10/20 Reading AutoProxyDetectType value*/


DWORD ReadAutoProxyDetectType(DWORD *pAutoProxyDetectType)
{

	DWORD error = ERROR_SUCCESS;
	DWORD valueLength;
	DWORD valueType;
	
	HKEY hInternetSettingsKey;

	error = RegOpenKeyEx(HKEY_CURRENT_USER,
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
		0,
		KEY_READ,
		&hInternetSettingsKey);

	if (error  == ERROR_SUCCESS)
	{
		//valueLength = sizeof(DWORD);
		error = (DWORD)RegQueryValueEx(hInternetSettingsKey,
			TEXT("AutoProxyDetectType"),
			NULL, // reserved
			&valueType,
			(LPBYTE)pAutoProxyDetectType,
			&valueLength
			);
		//
		// if the size or type aren't correct then return an error, else only if
		// success was returned do we modify *ParameterValue
		//

		if (error == ERROR_SUCCESS)
		{
			if (((valueType != REG_DWORD) && (valueType != REG_BINARY)) || (valueLength != sizeof(DWORD)))
			{
				error = ERROR_PATH_NOT_FOUND;
			}
		}
	}
	return error;
}


//16/9/24 2.2 major rewrite of command line parsing
//16/10/2 verbose parameter
//16/12/10 fix in ErrorString
//17/01/03 removing bUseIpAddress from most helper functions as only myIPAddress should use it
void DisplayHelp()
{
	printf("Help for AUTOPROX.EXE\r\n\r\n");
	printf("Version : 2.42\r\n");
	printf("Written by pierrelc@microsoft.com\r\n");
	printf("Usage : AUTOPROX -a  (calling DetectAutoProxyUrl and saving wpad.dat file in temporary file if success)\r\n");
	printf("Usage : AUTOPROX -n  (calling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DNS_A only and saving wpad.dat file in temporary file if success)\r\n");
	printf("Usage : AUTOPROX  [-o] [-d] [-v] [-u:url] [-p:Path to autoproxy file] [-i:IP address]\r\n");
	printf("       -o: calls InternetInitializeAutoProxyDll with helper functions implemented in AUTOPROX\r\n");
	printf("       -i:IP Address: calls InternetInitializeAutoProxyDll with helper functions implemented in AUTOPROX and using provided IP Address\r\n");
	printf("       -v: verbose output for helper functions\r\n");
	printf("For debugging: -d plus HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Script\\Settings\\JITDebug=1");
	printf("AUTOPROX -u:url: calling DetectAutoProxyUrl and using autoproxy file to find the proxy for the url\r\n");
	printf("AUTOPROX -u:url -p:path: using the autoproxy file/url from the path to find proxy for the url\r\n");
	printf("Example: autoprox http://www.microsoft.com -> calling DetectAutoProxyUrl and using WPAD if found\r\n");
	printf("Example: autoprox -o -u:http://www.microsoft.com -p:c:\\inetpub\\wwwroot\\wpad.dat\r\n");
	printf("Example: autoprox -u:http://www.microsoft.com -p:http://proxy/wpad.dat\r\n");
	printf("Example: autoprox -d -u:http://www.microsoft.com -p:http://proxy/wpad.dat\r\n");
	exit(-1);
}

/* ==================================================================
      * * * The  main( ) function of the test application  * * *
   ================================================================== */
int _tmain(int argc, _TCHAR* argv[])
{
	TCHAR Url[INTERNET_MAX_URL_LENGTH] = L"";
	char url[INTERNET_MAX_URL_LENGTH] = "";
	char host[MAX_PATH] = "";
	char WPADLocation[INTERNET_MAX_URL_LENGTH] = "";
	char TempPath[MAX_PATH];
	TCHAR File[MAX_PATH];
	char TempFile[MAX_PATH] = "";
	char TempDownload[MAX_PATH] = "";
	char proxyBuffer[1024];
	char* proxy = proxyBuffer;
	ZeroMemory(proxy, 1024);
	DWORD dwProxyHostNameLength = 1024;
	DWORD returnVal;
	HMODULE hModJS;
	BOOL bUseAutoDetection = FALSE;
	BOOL bWpadFileGivenAsArg = FALSE;
	BOOL bUseOwnHelperFunctions = FALSE;
	BOOL bUseUrl = FALSE;
	BOOL bAttachToDebugger = FALSE;
	BOOL bUseAutoFile = FALSE;
	BOOL bUseTempFile = FALSE;
	BOOL bUseDNSOnly = FALSE;

	HRESULT hr;
	DWORD dwError;


	// Declare and populate an AutoProxyHelperVtbl structure, and then 
	// place a pointer to it in a containing AutoProxyHelperFunctions 
	// structure, which will be passed to InternetInitializeAutoProxyDll
	AutoProxyHelperVtbl Vtbl =
	{
		IsResolvable,
		GetIPAddress,
		ResolveHostName,
		IsInNet,
		IsResolvableEx,
		GetIPAddressEx
	};
	AutoProxyHelperFunctions HelperFunctions = { &Vtbl };

	// Declare function pointers for the three autoproxy functions
	pfnInternetInitializeAutoProxyDll    pInternetInitializeAutoProxyDll;
	pfnInternetDeInitializeAutoProxyDll  pInternetDeInitializeAutoProxyDll;
	pfnInternetGetProxyInfo              pInternetGetProxyInfo;


	//Command line handling
	TCHAR arg[MAX_PATH];
	if (argc == 1) DisplayHelp();

	for (int i = 1; i < argc; i++)
	{
		wcscpy_s(arg, argv[i]);
		_wcsupr_s(arg);

		//Help
		if ((LoopStringUpper(arg, (TCHAR*)L"-h") != NULL) || (LoopStringUpper(arg, (TCHAR*)"-?") != NULL))
		{
			DisplayHelp();
			continue;
		};

		//autodetect
		if (LoopStringUpper(arg, (TCHAR*)L"-a") != NULL)
		{
			bUseAutoDetection = TRUE;
			continue;
		}
		//autodetect
		if (LoopStringUpper(arg, (TCHAR*)L"-n") != NULL)
		{
			bUseAutoDetection = TRUE;
			bUseDNSOnly = TRUE;
			continue;
		}

		//Helper functions
		if (LoopStringUpper(arg, (TCHAR*)L"-o") != NULL)
		{
			bUseOwnHelperFunctions = TRUE;
			continue;
		}

		//Helper functions
		if (LoopStringUpper(arg, (TCHAR*)L"-v") != NULL)
		{
			bVerboseHelpers = TRUE;
			continue;
		}

		//url given 
		if (LoopStringUpper(arg, (TCHAR*)L"-u:") != NULL)
		{
			wcscpy_s(Url, argv[i] + wcslen(L"-u:"));
			size_t i;
			wcstombs_s(&i, url, (size_t)INTERNET_MAX_URL_LENGTH,
				Url, (size_t)INTERNET_MAX_URL_LENGTH);
			printf("Seaching proxy for url : %s\r\n", url);
			bUseUrl = TRUE;
			continue;
		}

		//pac file given 
		if (LoopStringUpper(arg, (TCHAR*)L"-p:") != NULL)
		{
			wcscpy_s(File, argv[i] + wcslen(L"-p:"));
			size_t i;
			wcstombs_s(&i, TempFile, (size_t)MAX_PATH,
				File, (size_t)MAX_PATH);

			//Checking if file is an url or a path
			if ((LoopStringUpper(File, (TCHAR*)L"http:") != NULL) || (LoopStringUpper(File, (TCHAR*)L"https:") != NULL) || (LoopStringUpper(File, (TCHAR*)L"ftp:") != NULL) || (LoopStringUpper(File, (TCHAR*)L"ftps:") != NULL))
			{
				GetTempPathA(sizeof(TempPath) / sizeof(TempPath[0]), TempPath);
				GetTempFileNameA(TempPath, NULL, 0, TempDownload);
				printf("File located on an http server: downloading %s to %s\r\n", TempFile, TempDownload);
				hr = URLDownloadToFileA(NULL, TempFile, TempDownload, NULL, NULL);
				if (hr != S_OK)
				{
					printf("Downloading of %s failed\r\n", TempFile);
					printf("URLDownloadToFileA error : %X %d\r\n", hr, hr);
					reportFuncErr("URLDownloadToFileA");
				}
				strcpy_s(TempFile, TempDownload);
				bUseTempFile = TRUE;
			}

			//check that input file is valid
			returnVal = GetFileAttributesA(TempFile);
			if (returnVal == INVALID_FILE_ATTRIBUTES)
			{
				printf("\r\n>>>>>> Error accessing input file\r\n");
				reportFuncErr("GetFileAttributesA");
			}
							
			printf("Searching proxy using file : %s\r\n", TempFile);			
			bUseAutoFile = TRUE;
			continue;
		}

		//IP address given
		//url given 
		if (LoopStringUpper(arg, (TCHAR*)L"-i:") != NULL)
		{
			wcscpy_s(IpAddress, argv[i] + wcslen(L"-i:"));
			size_t i;
			wcstombs_s(&i, myIpAddress, (size_t)16,IpAddress, (size_t)16);
			bUseIpAddress = TRUE;
			bUseOwnHelperFunctions = TRUE;
			continue;
		}
		printf("Invalid parameter : %S\r\n", argv[i]);
		DisplayHelp();
	}

	//Checking logic of command line parameters
	//url given as input but no path for auto file -> forcing auto detection
	if (bUseUrl && (!(bUseAutoFile)))
	{
		//forcing auto detection
		printf("\r\n>>>>>> No file given as input: forcing autodetection\r\n");
		bUseAutoDetection = TRUE;
	}
	if (bUseAutoFile && (!(bUseUrl)))
	{
		printf("\r\n>>>>>> Invalid argument: Url missing\r\n\r\n");
		DisplayHelp();
	}
	if (bUseOwnHelperFunctions && (!(bUseUrl)))
	{
		printf("\r\n>>>>>> Invalid argument: Url missing\r\n\r\n");
		DisplayHelp();
	}

	if (bUseAutoDetection)
	{
		printf("Attempting to determine the location of autoproxy script\r\n");
		DWORD AutoProxyDetectType;
		dwError = ReadAutoProxyDetectType(&AutoProxyDetectType);
		if (dwError == ERROR_SUCCESS)
		{
			printf("AutoDetectProxyType value : %d\r\n", AutoProxyDetectType); 
			if (AutoProxyDetectType & 1)
			{
				printf("AutoDetectProxyType DHCP\r\n");
			}
			if (AutoProxyDetectType & 2)
			{
				printf("AutoDetectProxyType DNS\r\n");
			}
			printf("\r\n");
		}
		else
		{
			printf("AutoDetectProxyType value not found.\r\n\r\n");
		}

		if (bUseDNSOnly == TRUE)
		{
			printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DNS_A only\r\n");
			if (!DetectAutoProxyUrl(WPADLocation, sizeof(WPADLocation), PROXY_AUTO_DETECT_TYPE_DNS_A))
			{
				printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DNS_A failed with error: 0x%X %d\r\n", dwError, dwError);
				ErrorPrint();
				printf("Calling QueryWellKnownDnsName\r\n");
				if (QueryWellKnownDnsName((PSTR*)WPADLocation) != ERROR_SUCCESS)
				{
					reportFuncErr("DetectAutoProxyUrl");
				}
			}
		}
		else
		{
			printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DHCP first\r\n");
			if (!DetectAutoProxyUrl(WPADLocation, sizeof(WPADLocation), PROXY_AUTO_DETECT_TYPE_DHCP))
			{				
				dwError = GetLastError();
				printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DHCP failed with error: 0x%X %d\r\n", dwError, dwError);
				ErrorPrint();
				printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DNS_A only\r\n");
				if (!DetectAutoProxyUrl(WPADLocation, sizeof(WPADLocation), PROXY_AUTO_DETECT_TYPE_DNS_A))
				{
					printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DNS_A failed with error: 0x%X %d\r\n", dwError, dwError);
					ErrorPrint();
					printf("Calling QueryWellKnownDnsName\r\n");
					if (QueryWellKnownDnsName((PSTR*)WPADLocation) != ERROR_SUCCESS)
					{
						reportFuncErr("DetectAutoProxyUrl");
					}
				}
			}
			else
			{
				//16/10/21
				printf("\tCalling DetectAutoProxyUrl with PROXY_AUTO_DETECT_TYPE_DHCP succeeded\r\n");
			}
		}
		printf("\tWPAD Location is: %s\n", WPADLocation);

		GetTempPathA(sizeof(TempPath) / sizeof(TempPath[0]), TempPath);
		GetTempFileNameA(TempPath, NULL, 0, TempFile);
		printf("Calling URLDownloadToFile to download the autoproxy file to : %s\r\n", TempFile);
		hr = URLDownloadToFileA(NULL, WPADLocation, TempFile, NULL, NULL);
		if (hr != S_OK)
		{
			printf("URLDownloadToFileA error : %X (%d)\r\n", hr, hr);
			reportFuncErr("URLDownloadToFileA");
		}
		bUseTempFile = TRUE;
		printf("autoproxy file saved in %s\r\n", TempFile);
		//Dowload of autoproxy file only
		if (!(bUseUrl))
		{
			exit(0L);
		}
	}

	//for debugging : HKEY_CURRENT_USER\Software\Microsoft\Windows Script\Settings\JITDebug=1	
	//if (!(LoadLibraryA("jscript.dll")))
	//	reportFuncErr( "LoadLibrary jscript.dll");
	if (!(hModJS = LoadLibraryA("jsproxy.dll")))
		reportFuncErr( "LoadLibrary");


	if (!(pInternetInitializeAutoProxyDll = (pfnInternetInitializeAutoProxyDll)
		GetProcAddress(hModJS, "InternetInitializeAutoProxyDll")) ||
		!(pInternetDeInitializeAutoProxyDll = (pfnInternetDeInitializeAutoProxyDll)
		GetProcAddress(hModJS, "InternetDeInitializeAutoProxyDll")) ||
		!(pInternetGetProxyInfo = (pfnInternetGetProxyInfo)
		GetProcAddress(hModJS, "InternetGetProxyInfo")))
		reportFuncErr( "GetProcAddress");


	WSADATA wsaData;

	// Initialize Winsock  >>>> version 1.01 then 1.06 (fails on Win7 only!)
	returnVal = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (returnVal != NO_ERROR) {
		printf("WSAStartup failed with error %d\n", returnVal);
		return 1;
	}
	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 1;
	}
	else
		printf("The Winsock 2.2 dll was found okay\n");




	if (bUseOwnHelperFunctions == TRUE)
	{
		printf("Calling InternetInitializeAutoProxyDll with %s and using helper functions\r\n", TempFile);
		returnVal = pInternetInitializeAutoProxyDll(0, TempFile,
			NULL,
			&HelperFunctions,
			NULL);
		if (!(returnVal))
		{
			reportFuncErr( "InternetInitializeAutoProxyDll");
		}
	}
	else
	{
		printf("Calling InternetInitializeAutoProxyDll with %s\r\n", TempFile);
		if (!(returnVal = pInternetInitializeAutoProxyDll(0, TempFile,
			NULL,
			NULL,
			//&HelperFunctions, Rev 2.0 removing helper functions
			NULL)))
		{
			reportFuncErr("InternetInitializeAutoProxyDll");
		}
	}

	if (bUseUrl)
	{
		GetHost(url, host);

		printf("\tCalling InternetGetProxyInfo for url %s and host %s\r\n", url, host);
		if (!pInternetGetProxyInfo((LPSTR)url, sizeof(url),
			(LPSTR)host, sizeof(host),
			&proxy, &dwProxyHostNameLength))
		{
			reportFuncErr("InternetGetProxyInfo");
		}

		printf("\tProxy returned for url %s is:  \r\n%s\t\r\n\n", url, proxy);

		if (bAttachToDebugger)
		{
			printf("You can attach a script debugger and then press enter to continue.");
			getchar();
			printf("\tCalling InternetGetProxyInfo with url %s and host %s\r\n", url, host);
			if (!pInternetGetProxyInfo((LPSTR)url, sizeof(url),
				(LPSTR)host, sizeof(host),
				&proxy, &dwProxyHostNameLength))
			{
				reportFuncErr("InternetGetProxyInfo");
			}
			printf("\tProxy returned for url %s is:  \r\n%s\t\r\n\n", url, proxy);
		}
	}
	//Cleanup

	// Delete the temporary file if -a was not used
	if (bUseTempFile && (!(bUseAutoDetection)) && TempFile[0])
	{
		printf("\tDeleting the autoproxy script temporary file :\n%s\n", TempFile);
		DeleteFileA(TempFile);
	}

	if( !pInternetDeInitializeAutoProxyDll( NULL, 0 ) )
	{
		reportFuncErr("InternetDeInitializeAutoProxyDll" );
	}
	return( 0 );
}

//2.1.0.1

/*++

ErrorString:

This routine does it's very best to translate a given error code into a
text message.  Any trailing non-printable characters are striped from the
end of the text message, such as carriage returns and line feeds.

Arguments:

dwErrorCode supplies the error code to be translated.

Return Value:

The address of a freshly allocated text string.  Use FreeErrorString to
dispose of it.

Throws:

Errors are thrown as DWORD status codes.

Remarks:




--*/


LPCTSTR
ErrorString(DWORD dwErrorCode)
{
	LPTSTR szErrorString = NULL;
	DWORD dwLen;

	dwLen = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dwErrorCode,
		LANG_NEUTRAL,
		(LPTSTR)&szErrorString,
		0,
		NULL);

	if ((0 == dwLen) || (szErrorString == NULL))
	{
		//ASSERT(NULL == szErrorString);
		dwLen = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER
			| FORMAT_MESSAGE_FROM_HMODULE,
			GetModuleHandle(L"wininet"),
			dwErrorCode,
			LANG_NEUTRAL,
			//MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),  
			//LANG_INVARIANT,
			//GetSystemDefaultLangID(),
			(LPTSTR)&szErrorString,
			0,
			NULL);
		//printf("dwLen 2:%d %X \n", dwLen, szErrorString);
		if (0 == dwLen)
		{
			//ASSERT(NULL == szErrorString);
			if (szErrorString != NULL)
			{
				printf("Assertion failure: szErrorString should be NULL as FormatMessage failed\n");
			}
		}
	}

	//Required for localization !!!
	if (szErrorString != NULL)
	{
		char OEMString[256];
		//2.41 
		CharToOemBuff(szErrorString, (LPSTR)OEMString, wcslen(szErrorString));
		printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, OEMString);
	}
	else
	{
		/*
		C:\Temp>err 2f92
		# for hex 0x2f92 / decimal 12178
		ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR                         winhttp.h
		# 1 matches found for "2f92"*/
		/*if (dwErrorCode == 0x2F92)
		{
			printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, "ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR");
		}
		else
		{
			printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, "Unable to get error message");
		}*/

		//Trying winHTTP
		dwLen = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER
			| FORMAT_MESSAGE_FROM_HMODULE,
			GetModuleHandle(L"winhttp"),
			dwErrorCode,
			LANG_NEUTRAL,
			//MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),  
			//LANG_INVARIANT,
			//GetSystemDefaultLangID(),
			(LPTSTR)&szErrorString,
			0,
			NULL);
		//printf("dwLen 2:%d %X \n", dwLen, szErrorString);
		if (0 == dwLen)
		{
			//ASSERT(NULL == szErrorString);
			if (szErrorString != NULL)
			{
				printf("Assertion failure: szErrorString should be NULL as FormatMessage failed\n");
			}
		}

		//Required for localization !!!
		if (szErrorString != NULL)
		{
			char OEMString[256];
			CharToOemBuff(szErrorString, (LPSTR)OEMString, wcslen(szErrorString));
			printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, OEMString);
		}
		else
		{		
			printf("\n(%d) (0x%X) %s\n", dwErrorCode, dwErrorCode, "Unable to get error message from WinINet or WinHTTP\r\n");
		}
	}
	//SetConsoleCP(863);
	//printf("%d\n",GetConsoleCP());
	return szErrorString;
}




/*++

FreeErrorString:

This routine frees the Error String allocated by the ErrorString service.

Arguments:

szErrorString supplies the error string to be deallocated.

Return Value:

None

Throws:

None

Remarks:




--*/

void
FreeErrorString(
	LPCTSTR szErrorString)
{
	if (NULL != szErrorString)
		LocalFree((LPVOID)szErrorString);
}


void ErrorPrint()
{
	ErrorString(GetLastError());
	return;
}
/////////////////////////////////////////////////////////////////////
//  reportFuncErr                            (simple error reporting)
/////////////////////////////////////////////////////////////////////
void reportFuncErr(char* funcName)
{
	//Rev 1.3
	DWORD dwError;
	dwError = GetLastError();
	printf("\n  ERROR: %s failed with error number 0x%x %d.\n", funcName,
		dwError, dwError);
	ErrorPrint();
	exit(-1);
}

DWORD
QueryWellKnownDnsName(
	__out PSTR *ppszAutoProxyUrl
	)
	/*++

	Routine Description:

	This function walks a list of standard DNS names trying to find
	an entry for "wpad.some-domain-here.org"  If it does, it constructs
	an URL that is suitable for use in auto-proxy.

	Arguments:

	ppwszAutoProxyUrl - Upon success, an allocated auto proxy url, should be freed by caller.

	Return Value:

	ERROR_SUCCESS - if we found a URL/DNS name

	ERROR_NOT_FOUND - on error

	--*/
{
#define PROXY_AUTO_DETECT_PATH "wpad.dat"

	DWORD dwError = ERROR_SUCCESS;
	HRESULT hr = S_OK;
	//NTSTATUS ntStatus = STATUS_SUCCESS;
	const CHAR szHostDomain[32] = "wpad";
	ADDRINFO *pAddrInfo = NULL;
	ADDRINFO *pFreeAddrInfo = NULL;
	ADDRINFO Hints = {};
	//DWORD cchAddrBuff = ARRAYSIZE(wszAddrBuff);
	PSOCKADDR_IN pSockAddr4 = NULL;
	PSOCKADDR_IN6 pSockAddr6 = NULL;
	DWORD cchAutoProxyUrl = 0;
	const CHAR *pszNameToUse = NULL;


	*ppszAutoProxyUrl = NULL;

	// use FQDN as hostname if getaddrinfo returns one instead of IP address
	Hints.ai_flags = AI_CANONNAME;

	/*if (g_fAllowOnlyDNSQueryForWPAD)
	{
		Hints.ai_flags |= AI_DNS_ONLY;
	}*/

	Hints.ai_family = PF_UNSPEC;      // Accept any protocol family.
	Hints.ai_socktype = SOCK_STREAM;  // Constrain results to stream socket.
	Hints.ai_protocol = IPPROTO_TCP;  // Constrain results to TCP.
	
	printf("QueryWellKnownDNSName. Calling getaddrinfo with name wpad\r\n");
	dwError = getaddrinfo(szHostDomain, NULL, &Hints, &pAddrInfo);
	
	if (dwError != 0)
	{
		printf("QueryWellKnownDNSName. getaddrinfo returns error: %d\n", dwError);
		ErrorPrint();
		dwError = ERROR_NOT_FOUND;
		goto quit;
	}

	pFreeAddrInfo = pAddrInfo;

	if (pAddrInfo->ai_canonname != NULL)
	{
		// use FQDN returned from getaddrinfo
		pszNameToUse = pAddrInfo->ai_canonname;
		printf("QueryWellKnownDNSName. pAddrInfo->ai_canonname:  %s\r\n", pszNameToUse);
	}
	else
	{
		printf("QueryWellKnownDNSName. pAddrInfo->ai_canonname null\r\n");
		while (pAddrInfo != NULL &&
			pAddrInfo->ai_family != PF_INET &&
			pAddrInfo->ai_family != PF_INET6)
		{
			pAddrInfo = pAddrInfo->ai_next;
		}

		if (pAddrInfo == NULL)
		{
			// No IP addresses found
			dwError = ERROR_NOT_FOUND;
			goto quit;
		}

		if (pAddrInfo->ai_family == PF_INET)
		{
			pSockAddr4 = (PSOCKADDR_IN)pAddrInfo->ai_addr;

			/*ntStatus = RtlIpv4AddressToStringExW(&pSockAddr4->sin_addr,
				pSockAddr4->sin_port,
				wszAddrBuff,
				&cchAddrBuff);*/
		}
		else
		{
			//WX_ASSERT(pAddrInfo->ai_family == PF_INET6);
			pSockAddr6 = (PSOCKADDR_IN6)pAddrInfo->ai_addr;

			//
			// As long as we supply a port we get the information back
			// with brackets as desired.  If a port is not returned use
			// default HTTP port. i.e.
			// [fe80::2dac:3fee:f54c:6f08%5]:80
			//
			if (pSockAddr6->sin6_port == 0)
			{
				//pSockAddr6->sin6_port = NETWORKBYTEORDER_PORT80;
			}

			/*ntStatus = RtlIpv6AddressToStringExW(&pSockAddr6->sin6_addr,
				pSockAddr6->sin6_scope_id,
				pSockAddr6->sin6_port,
				wszAddrBuff,
				&cchAddrBuff);*/
		}
		//WX_ASSERT(NT_SUCCESS(ntStatus));
		/*if (!NT_SUCCESS(ntStatus))
		{
			dwError = RtlNtStatusToDosError(ntStatus);
			goto quit;
		}*/

		//pszNameToUse = szAddrBuff;
	}

	//
	// dwAutoProxyUrlLength should contain the size of the resulting
	// URL + 1 null terminator.
	//
	cchAutoProxyUrl = (DWORD)(strlen(pszNameToUse) +
		strlen("http:///") +
		strlen(PROXY_AUTO_DETECT_PATH) +
		1);
	if (cchAutoProxyUrl >= INTERNET_MAX_URL_LENGTH)
	{
		printf("QueryWellKnownDNSName. Path too long. Name to use: %s\n", pszNameToUse);
	}
	hr = sprintf_s((char*)ppszAutoProxyUrl,
		cchAutoProxyUrl,
		"http://%s/%s",
		pszNameToUse,
		PROXY_AUTO_DETECT_PATH);
	if (FAILED(hr))
	{
		goto quit;
	}
	else
	{
		return ERROR_SUCCESS;
	}

quit:
	printf( "QueryWellKnownDNSName returning error:  %d", dwError);
	ErrorPrint();
	return dwError;
}
