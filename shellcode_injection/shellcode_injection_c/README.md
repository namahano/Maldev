# shellcode injection PoC

# Usage

```
.\shellcode_injection.exe <PID>
```

Launch Notepad.exe

```
notepad.exe
```

Identify the PID of Notepad.exe

```
PS C:\Users\hatto> tasklist | findstr Notepad.exe
Notepad.exe                   8820 Console                    5     81,496 K
```

Execute with the obtained PID as an argument

```
.\shellcode_injection.exe 8820
```
