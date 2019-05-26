# NamedPipeImpersonation

 - Simple POC for Named Pipe Impersonation.
 - Creates a namedpipe haxx.
 - Executing user should have SeImpersonatePrivilege.
 - Hardcoded to execute C:\ProgramData\pwn.bat.
 - Compile with mingw: x86_64-w64-mingw32-gcc -D UNICODE NamedPipes.c -o exploit.exe
 
 In case the Secondary Logon Service is disabled use the CreateFile PoC to write files as the client.
