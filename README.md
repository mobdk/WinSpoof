# WinSpoof
Use TpAllocWork, TpPostWork and TpReleaseWork to execute machine code

This PoC code demostrate how TpAllocWork, TpPostWork and TpReleaseWork can be used to execute machine code, the code start a image file
by calling: 

  TpAllocWork ---> RtlCreateProcessParametersEx
  TpAllocWork ---> ZwCreateUserProcess (syscalled)
  TpAllocWork ---> ZwResumeThread (syscalled)
  TpAllocWork ---> RtlDestroyProcessParameters
  
All API calls happens in memory only, no reference to ntdll og kernel32 on file system, so the machine code can be obfuscated, calls to 
function in kernel32 (in memory) is done by resolving the base address of kernel32 and then lookup the hash value of the function and then:

  movabs rax, FunctionPtr
  jmp rax
  
Function in ntdll (in memory) use the same steps, but insted of using the classic 11 byte syscall, it uses 313 bytes.

When WinSpoof is executed, cmd.exe is spoofed to whatever parent process you like, in the context it is running, Microsoft Signatures restricted
is also used.

Running only on 64 bit Windows 10.

Compile:

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:x64 /target:exe /unsafe WinSpoof.cs

If you don't change the source code, you have to start 2 processes:

  "cmd remote"
  "cmd spoofed"
  
From the "cmd remote" console, start WinSpoof.exe, WinSpoof will find the process cmd with argument spoofed, and the execute cmd.exe as an
sub process.




