# Dr.Semu

`Dr.Semu` runs executables in an isolated environment, monitors the behavior of a process, and based on `Dr.Semu` rules created by you or community, detects if the process is malicious or not.

**[The tool is in the early development stages]**
#### whoami: [@_qaz_qaz](https://twitter.com/_qaz_qaz)

`Dr.Semu` let you to create rules for different malware families and detect new samples based on their behavior.


### Isolation through redirection

Everything happens from the user-mode. Windows Projected File System [(ProjFS)](https://docs.microsoft.com/en-us/windows/win32/projfs/projected-file-system) is used to provide a `virtual` file system. For Registry redirection, it copies all Registry hives to a new location and redirects all Registry accesses (after caching Registry hives, all subsequent executions are very fast, ~0.3 sec.)

See the source code for more about other redirections (process/objects isolation, etc).

### Monitoring

`Dr.Semu` uses [Dynamorio](https://github.com/DynamoRIO/dynamorio) (Dynamic Instrumentation Tool Platform) to intercept a thread when it's about to cross the user-kernel line. It has the same effect as hooking `SSDT` but from the user-mode and without hooking anything.

At this phase, `Dr.Semu` produces a JSON file, which contains information from the interception.

### Detection

After terminating the process, based on `Dr.Semu` rules we receive if the executable is detected as malware or not.

### Dr.Semu rules

They are written in `LUA` and use dynamic information from the interception and static information about the sample. It's trivial to add support of other languages.

Example: https://gist.github.com/secrary/e16daf698d466136229dc417d7dbcfa3

### Usage

- Use `PowerShell` to enable `ProjFS` in an elevated `PowerShell` window:

`Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`

- Download and extract a zip file from the [releases page](https://github.com/secrary/DrSemu/releases)

- Download `DynamoRIO` and extract into `DrSemu` folder and rename to [`dynamorio`](https://github.com/DynamoRIO/dynamorio/releases)


`DrSemu.exe --target file_path`

`DrSemu.exe --target files_directory`


### DEMO

[![DrSemu DEMO](https://user-images.githubusercontent.com/16405698/63061859-36a43f00-bee6-11e9-8b51-f053dfe2ec54.PNG)](https://www.youtube.com/watch?v=Ylfv8EFffoY "DrSemu Detection - DEMO")

### BUILD
* Use `PowerShell` to enable `ProjFS` in an elevated `PowerShell` window:

`Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`

![powershell](https://user-images.githubusercontent.com/16405698/63098792-35fdbe00-bf63-11e9-8dec-0ae08c43fca1.PNG)


* Download `DynamoRIO` and extract into `bin` folder and rename to [`dynamorio`](https://github.com/DynamoRIO/dynamorio/releases)

* Build [`pe-parser-library.lib`](https://github.com/trailofbits/pe-parse) library:
  - Generate VS project from `DrSemu\shared_libs\pe_parse` using [cmake-gui](https://cmake.org/download/)
  - Build 32-bit library under `build` (`\shared_libs\pe_parse\build\pe-parser-library\Release\`) and 64-bit one under `build64`
  - Change run-time library option to `Multi-threaded` (`/MT`)

* Set `LauncherCLI` As StartUp Project


### TODO

- Solve isolation related issues
- Update the description, add more details
- Create a GUI for the tool

### Limitations

- Minimum supported Windows version: `Windows 10`, version 1809 (due to `Windows Projected File System`)
- Maximum supported Windows version: `Windows 10`, version 1809 (`DynamoRIO` supports `Windows 10` versions until `1809`)
