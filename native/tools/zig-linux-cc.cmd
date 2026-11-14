@echo off
setlocal
set "args="

:collect
if "%~1"=="" goto link
set "arg=%~1"
if not "%arg:~0,1%"=="@" goto direct
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0filter-zig-linker-response.ps1" "%arg:~1%"
if errorlevel 1 exit /b 1
goto keep

:direct
if "%~1"=="--target=x86_64-unknown-linux-gnu" goto skip
if "%~1"=="-Wl,-znostart-stop-gc" goto skip

:keep
set "args=%args% %1"

:skip
shift
goto collect

:link
zig cc -target x86_64-linux-gnu %args%
