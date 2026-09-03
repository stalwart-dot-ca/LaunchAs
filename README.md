==============================================================================
⚠️ CRITICAL SECURITY WARNING: UI-DERIVED PRIVILEGE ESCALATION
==============================================================================

`LaunchAs` executes target applications with elevated administrative tokens
in an interactive user session.  Administrators MUST exercise caution when 
selecting which applications to register.

THE COMMON FILE DIALOG BREAKOUT VECTOR:

	If you register an application that exposes standard Win32 file dialogs 
	(e.g., "File -> Open", "Save As", Print Dialogs, or Help Menus), a non-
	admin user can easily escape the application sandbox.

	By navigating the elevated file dialog, a user can right-click any 
	executable or system utility (such as cmd.exe) and launch it with the 
	same administrative privileges inherited by the parent program.

BEST PRACTICES FOR SECURE DEPLOYMENT:

	1. TARGET LOCKED-DOWN APPS: Only register applications that do not allow 
	   arbitrary file system browsing, command execution, or plugin loading 
	   (e.g., secure browsers like Exam4, dedicated kiosks, or locked 
	   utility tools).

	2. NEVER ELEVATE SHELL APPS: Do not register text editors (Notepad), web 
	   browsers, document viewers, or command interpreters (cmd.exe, 
	   powershell.exe) for standard users unless the environment is strictly 
	   isolated.

	3. RESTRICT CLIENT ARGS: Keep `/allow_client_args` disabled (the default 
	   Strict Mode) unless absolutely required, preventing users from 
	   passing debug switches or interpreter execution flags.

==============================================================================

LaunchAs

	A secure Windows service bridge to launch designated applications with 
	elevated administrator privileges from standard user sessions without 
	UAC prompts or plaintext credentials.

Overview

	LaunchAs solves the “Session 0” isolation problem—where elevated 
	applications launched from a service fail to render their GUI or connect 
	to the Desktop Window Manager (DWM). It provides a hardened, multi-
	instance administrative bridge designed for lab, kiosk, and locked-down 
	environments.

Core Security Features

	- Machine-Bound Security: Credentials are encrypted using Windows DPAPI 
	  (CRYPTPROTECT_LOCAL_MACHINE) and LSA machine-keys. They cannot be 
	  decrypted on any other machine.

	- Zero Plaintext Exposure: Administrative passwords are never passed via 
	  command line, stored in configuration files, or transmitted over IPC 
	  pipes.

	- Strict Execution Control: The service is bound to a pre-registered 
	  executable path and working directory at the time of installation.

	- Foreground Handover: Implements advanced Win32 input-queue attachment 
	  to ensure elevated GUIs correctly grab focus and appear in the 
	  foreground of the user’s active session.

Quick Start (Administrator)

	1. Register the application:

		LaunchAs.exe /register /key="MyApp" /target="C:\Path\To\App.exe" /cwd="C:\Path\To\"

		The system will prompt you for the administrative credentials 
		once, then store them securely.

	2. Launch the application (Standard User):

		LaunchAs.exe /key="MyApp"

Advanced Features

	- Multi-Instance Isolation: Every /key creates a unique Windows service 
	  instance with its own isolated credential store.

	- Desktop Bridging: Automatically modifies Object DACLs (winsta0\default) 
	  to permit UI rendering from the elevated token into the active 
	  interactive session.

	- Audit-Ready: Logs all launch requests and process PIDs to 
	  %ProgramData%\LaunchAs\.

Building from Source

	Requires Visual Studio 2022 and the x64 Native Tools Command Prompt.

		vcvars64.bat
		cl /EHsc /O2 /MT /GS /guard:cf /nologo LaunchAs.cpp /Fe"LaunchAs.exe" /link /SUBSYSTEM:WINDOWS /ENTRY:wWinMainCRTStartup /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /MANIFEST:EMBED /MANIFESTUAC:NO /MANIFESTINPUT:LaunchAs.manifest

Security Disclosure

	Registration must be performed by an Administrator to ensure the 
	integrity of the target binary and the credential store.

	Standard users lack permissions to create services or modify the 
	credential storage directory.

🎗️ Support the Author / Medical Campaign

	LaunchAs is free and open-source software engineered to solve complex 
	Windows session and elevation challenges.  I am currently undergoing 
	treatment for Stage IV cancer.  If this utility saves you or your 
	organization time, or provides value in your environment, please 
	consider supporting my medical treatment fund:

		https://www.givesendgo.com/stalwart

	Every contribution and share is deeply appreciated and helps me continue 
	fighting and building.
