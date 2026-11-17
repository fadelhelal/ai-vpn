#define AppName "AI VPN"
#define AppExeName "AIVPN.exe"
#define AppPublisher "AIVPN contributors"
#define AppURL "https://example.invalid/aivpn"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{C4FA4D23-C88F-44C7-A63D-F64B02776453}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={autopf}\AI VPN
DefaultGroupName=AI VPN
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=AI-VPN-Windows-{#AppVersion}-Setup
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\AIVPN.exe
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription=AI VPN installer
VersionInfoCompany={#AppPublisher}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\AIVPN\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\AI VPN"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\AI VPN"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch AI VPN"; Flags: nowait postinstall skipifsilent
