@echo off
setlocal

:: Only call vcvars64.bat if the compiler is NOT already in the PATH
where cl >nul 2>nul
if %errorlevel% neq 0 (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
        call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    )
)

:: Compile and Link
cl /EHsc /O2 /MT /GS /guard:cf /nologo "LaunchAs.cpp" /Fe"LaunchAs.exe" /link /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /MANIFEST:EMBED /MANIFESTUAC:NO /MANIFESTINPUT:"LaunchAs.manifest"

:: signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "LaunchAs.exe"

endlocal
