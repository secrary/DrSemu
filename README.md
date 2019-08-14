# Dr.Semu

`Dr.Semu` runs executables in an isolated environment, monitors the behavior of a process, let you to create rules and based on the rules detect if the process is malicious or not.

**[The tool is in early development stage]**

`Dr.Semu` let you to create rules for different malware families and detect new samples based on their behavior.


### Isolation through redirection

Everything happens from a user-mode. Windows Projected File System [(ProjFS)](https://docs.microsoft.com/en-us/windows/win32/projfs/projected-file-system) is used to provide a `virtual` file system. For Registry redirection, it copies all Registry hives to a new location and redirects all Registry accesses.
See the source code about other redirections (process/objects isolation, etc).

### Monitoring

`Dr.Semu` uses [Dynamorio](https://github.com/DynamoRIO/dynamorio) (Dynamic Instrumentation Tool Platform) to intercept a thread when it's about to cross the user-kernel line. It has the same effect as hooking `SSDT` but from the user-mode and without hooking anything.
At this phase, `Dr.Semu` produces a JSON file, which contains information from the interception.

### Detection

After terminating the process, based on `Dr.Semu` rules we receive if the executable is detected as malware or not.

### Dr.Semu rules

They are written in `LUA` and use dynamic information from the interception and static information about the sample. It's trivial to add support of other languages.

Example: https://gist.github.com/secrary/e16daf698d466136229dc417d7dbcfa3

### Usage

- Download and extract a zip file from the [releases page](https://github.com/secrary/DrSemu/releases)
- Download [Dynamorio](https://github.com/DynamoRIO/dynamorio) build and extract into previously downloaded folder

`DrSemu.exe --target file_path`

`DrSemu.exe --target files_directory`

### DEMO

[![DrSemu DEMO](https://user-images.githubusercontent.com/16405698/63061859-36a43f00-bee6-11e9-8b51-f053dfe2ec54.PNG)](https://www.youtube.com/watch?v=Ylfv8EFffoY "DrSemu Detection - DEMO")

### BUILD


### TODO

- Solve isolation related issues
- Update the description, add more details
- Create a GUI for the tool

### Limitations

- Minimum supported Windows version: Windows 10, version 1809 (due to `Windows Projected File System`)
- Maximum supported Windows version: Windows 10, version 1809 (due to `DynamoRIO` only supported until 1809)
