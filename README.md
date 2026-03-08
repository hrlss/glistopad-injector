# glistopad-injector
DLL Injector

## Features
- CreateRemoteThread + LoadLibraryA injection
- Auto-detects DLL in the same folder
- Supports config.ini for target process & DLL path
- Multi-instance support — injects into all matching processes
- Skips already-loaded DLLs
- Colored console output with detailed logs

## Usage
Run as Administrator:
injector.exe target.exe payload.dll

Or create config.ini next to the exe:
process=target.exe
dll=payload.dll
