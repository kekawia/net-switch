#ifndef AppVersion
  #error Pass /DAppVersion via scripts/build-windows-installer.ps1
#endif
#ifndef StageDir
  #error Pass /DStageDir with the allowlisted staging directory
#endif
#ifndef OutputDir
  #error Pass /DOutputDir with the installer output directory
#endif
#ifndef AppArch
  #error Pass /DAppArch (x64 or arm64) via scripts/build-windows-installer.ps1
#endif
#if AppArch == "arm64"
  #define AllowedArch "arm64"
#elif AppArch == "x64"
  #define AllowedArch "x64compatible"
#else
  #error AppArch must be x64 or arm64
#endif

[Setup]
AppId={{3ECce0AD-AE44-4768-8219-2C15C098976C}
AppName=Net Switch
AppVersion={#AppVersion}
AppPublisher=Net Switch
DefaultDirName={autopf}\Net Switch
DefaultGroupName=Net Switch
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed={#AllowedArch}
ArchitecturesInstallIn64BitMode={#AllowedArch}
#if AppArch == "arm64"
MinVersion=10.0.22000
#else
MinVersion=10.0.19045
#endif
SetupIconFile={#StageDir}\assets\net-switch.ico
UninstallDisplayIcon={app}\assets\net-switch.ico
OutputDir={#OutputDir}
OutputBaseFilename=NetSwitch-Setup-{#AppVersion}-{#AppArch}
Compression=lzma2
SolidCompression=yes
CloseApplications=no
RestartApplications=no
UninstallLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
; StageDir is extracted into {tmp}\stage during PrepareToInstall so netswitchctl
; validates hashes, stages {app}\app-{#AppVersion}, and commits or rolls back
; atomically before Inno Setup modifies [Files], shortcuts, or Uninstall entries.
Source: "{#StageDir}\*"; DestDir: "{tmp}\stage"; Flags: dontcopy noencryption recursesubdirs createallsubdirs
Source: "{#StageDir}\assets\net-switch.ico"; DestDir: "{app}\assets"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Net Switch"; Filename: "{app}\netswitch-desktop.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\net-switch.ico"
Name: "{autodesktop}\Net Switch"; Filename: "{app}\netswitch-desktop.exe"; WorkingDir: "{app}"; IconFilename: "{app}\assets\net-switch.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\netswitch-desktop.exe"; WorkingDir: "{app}"; Description: "Open Net Switch"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
var
  StageExtracted: Boolean;
  CallerChecked: Boolean;
  OriginalCallerSID: String;
  ProfilePage: TInputOptionWizardPage;
  ProfileSIDs: TArrayOfString;
  DeleteMachineData: Boolean;
  UninstallCtlPath: String;

function ReadFirstTrimmedLine(const FilePath: String): String;
var
  Lines: TArrayOfString;
begin
  Result := '';
  if FileExists(FilePath) and LoadStringsFromFile(FilePath, Lines) then
    if GetArrayLength(Lines) > 0 then
      Result := Trim(Lines[0]);
end;

function EnsureStageExtracted: Boolean;
begin
  if not StageExtracted then begin
    ExtractTemporaryFiles('{tmp}\stage\*');
    StageExtracted := FileExists(ExpandConstant('{tmp}\stage\netswitchctl.exe'));
  end;
  Result := StageExtracted;
end;

function DetectOriginalCallerSID: String;
var
  ExplicitOwner, SidFile: String;
  ExitCode: Integer;
begin
  ExplicitOwner := Trim(ExpandConstant('{param:OWNER|}'));
  if ExplicitOwner <> '' then begin
    Result := ExplicitOwner;
    Exit;
  end;
  if not CallerChecked then begin
    CallerChecked := True;
    OriginalCallerSID := '';
    if EnsureStageExtracted then begin
      SidFile := ExpandConstant('{tmp}\caller-sid.txt');
      DeleteFile(SidFile);
      ExitCode := -1;
      try
        if ExecAsOriginalUser(ExpandConstant('{tmp}\stage\netswitchctl.exe'),
          'whoami --sid-out "' + SidFile + '"', ExpandConstant('{tmp}\stage'),
          SW_HIDE, ewWaitUntilTerminated, ExitCode) and (ExitCode = 0) then
          OriginalCallerSID := ReadFirstTrimmedLine(SidFile);
      except
        Log('ExecAsOriginalUser whoami unavailable; falling back to WTS session detection.');
      end;
    end;
  end;
  Result := OriginalCallerSID;
end;

procedure InitializeWizard;
var
  TargetAppDir, WizFile, CallerSID, Params, Line, Rest, ProfSID, ProfLabel, SelectedSID: String;
  Lines: TArrayOfString;
  ExitCode, I, SepPos, Count, DefaultIdx: Integer;
  IsConflict: Boolean;
begin
  ProfilePage := nil;
  SetArrayLength(ProfileSIDs, 0);
  if WizardSilent or (Trim(ExpandConstant('{param:PROFILE|}')) <> '') then
    Exit;
  TargetAppDir := WizardDirValue;
  if not FileExists(AddBackslash(TargetAppDir) + 'server.mjs') then
    Exit;
  if not EnsureStageExtracted then
    Exit;

  WizFile := ExpandConstant('{tmp}\profiles-wizard.txt');
  DeleteFile(WizFile);
  CallerSID := DetectOriginalCallerSID;
  Params := 'migrate-profiles --app-dir "' + TargetAppDir + '" --wizard-out "' + WizFile + '"';
  if CallerSID <> '' then
    Params := Params + ' --owner "' + CallerSID + '"';

  ExitCode := -1;
  if not Exec(ExpandConstant('{tmp}\stage\netswitchctl.exe'), Params,
    ExpandConstant('{tmp}\stage'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Exit;
  if (ExitCode <> 0) or (not LoadStringsFromFile(WizFile, Lines)) then
    Exit;

  IsConflict := False;
  SelectedSID := '';
  for I := 0 to GetArrayLength(Lines) - 1 do begin
    Line := Trim(Lines[I]);
    if Line = 'CONFLICT=1' then
      IsConflict := True
    else if Copy(Line, 1, 9) = 'SELECTED=' then
      SelectedSID := Copy(Line, 10, Length(Line) - 9);
  end;
  if not IsConflict then
    Exit;

  ProfilePage := CreateInputOptionPage(wpSelectDir,
    'Keep Net Switch settings',
    'More than one Windows account on this PC has saved Net Switch settings.',
    'Choose which account''s settings and usage history to bring into Net Switch:',
    True, False);

  Count := 0;
  DefaultIdx := 0;
  for I := 0 to GetArrayLength(Lines) - 1 do begin
    Line := Trim(Lines[I]);
    if Copy(Line, 1, 8) = 'PROFILE=' then begin
      Rest := Copy(Line, 9, Length(Line) - 8);
      SepPos := Pos('|', Rest);
      if SepPos > 1 then begin
        ProfSID := Copy(Rest, 1, SepPos - 1);
        ProfLabel := Copy(Rest, SepPos + 1, Length(Rest) - SepPos);
        SetArrayLength(ProfileSIDs, Count + 1);
        ProfileSIDs[Count] := ProfSID;
        ProfilePage.Add(ProfLabel);
        if ProfSID = SelectedSID then
          DefaultIdx := Count;
        Count := Count + 1;
      end;
    end;
  end;
  if Count > 0 then
    ProfilePage.SelectedValueIndex := DefaultIdx;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  CtlExe, AppPath, ErrFile, CallerSID, ChosenProfile, SubCmd, Params, ErrMsg: String;
  ExitCode: Integer;
begin
  Result := '';
  NeedsRestart := False;
  if not EnsureStageExtracted then begin
    Result := 'Net Switch staging files could not be extracted.';
    Exit;
  end;

  CtlExe := ExpandConstant('{tmp}\stage\netswitchctl.exe');
  AppPath := ExpandConstant('{app}');
  ErrFile := ExpandConstant('{tmp}\install-error.txt');
  DeleteFile(ErrFile);

  CallerSID := DetectOriginalCallerSID;
  ChosenProfile := Trim(ExpandConstant('{param:PROFILE|}'));
  if (ChosenProfile = '') and (ProfilePage <> nil) and
     (ProfilePage.SelectedValueIndex >= 0) and
     (ProfilePage.SelectedValueIndex < GetArrayLength(ProfileSIDs)) then
    ChosenProfile := ProfileSIDs[ProfilePage.SelectedValueIndex];

  if FileExists(AddBackslash(AppPath) + 'server.mjs') then begin
    SubCmd := 'migrate';
    Params := 'migrate --stage-dir "' + ExpandConstant('{tmp}\stage') +
      '" --app-dir "' + AppPath +
      '" --version "{#AppVersion}" --error-out "' + ErrFile + '"';
    if ChosenProfile <> '' then
      Params := Params + ' --profile "' + ChosenProfile + '"';
  end else begin
    SubCmd := 'install';
    Params := 'install --stage-dir "' + ExpandConstant('{tmp}\stage') +
      '" --app-dir "' + AppPath +
      '" --version "{#AppVersion}" --error-out "' + ErrFile + '"';
  end;
  if CallerSID <> '' then
    Params := Params + ' --owner "' + CallerSID + '"';

  ExitCode := -1;
  if not Exec(CtlExe, Params, ExpandConstant('{tmp}\stage'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then begin
    Result := 'Net Switch setup helper could not be started.';
    Exit;
  end;
  Log(Format('netswitchctl %s exit code: %d', [SubCmd, ExitCode]));
  if ExitCode <> 0 then begin
    ErrMsg := ReadFirstTrimmedLine(ErrFile);
    if ErrMsg = '' then
      ErrMsg := Format('Net Switch %s failed (exit %d). No committed changes were made.', [SubCmd, ExitCode]);
    Log('PrepareToInstall failed: ' + ErrMsg);
    Result := ErrMsg;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  CtlExe: String;
  ExitCode: Integer;
begin
  if CurStep = ssPostInstall then begin
    CtlExe := ExpandConstant('{app}\app-{#AppVersion}\netswitchctl.exe');
    if FileExists(CtlExe) then begin
      ExitCode := -1;
      Exec(CtlExe, 'harden-root --app-dir "' + ExpandConstant('{app}') + '"',
        ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ExitCode);
      Log(Format('netswitchctl harden-root exit code: %d', [ExitCode]));
    end;
  end;
end;

function FindInstalledCtl: String;
var
  AppRoot, Marker, Candidate: String;
  FindRec: TFindRec;
begin
  Result := '';
  AppRoot := ExpandConstant('{app}');
  Marker := ReadFirstTrimmedLine(AddBackslash(AppRoot) + 'current');
  if (Marker <> '') and (Copy(Marker, 1, 4) = 'app-') then begin
    Candidate := AddBackslash(AppRoot) + Marker + '\netswitchctl.exe';
    if FileExists(Candidate) then begin
      Result := Candidate;
      Exit;
    end;
  end;
  if FindFirst(AddBackslash(AppRoot) + 'app-*', FindRec) then begin
    try
      repeat
        if ((FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0) and
           ((FindRec.Attributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0) then begin
          Candidate := AddBackslash(AppRoot) + FindRec.Name + '\netswitchctl.exe';
          if FileExists(Candidate) then
            Result := Candidate;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure RemoveManagedAppFiles;
var
  AppRoot, Target: String;
  FindRec: TFindRec;
begin
  AppRoot := ExpandConstant('{app}');
  DeleteFile(AddBackslash(AppRoot) + 'current');
  DeleteFile(AddBackslash(AppRoot) + 'netswitch-desktop.exe');
  if DirExists(AddBackslash(AppRoot) + 'updates') then
    DelTree(AddBackslash(AppRoot) + 'updates', True, True, True);
  if FindFirst(AddBackslash(AppRoot) + 'app-*', FindRec) then begin
    try
      repeat
        if ((FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0) and
           ((FindRec.Attributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0) and
           (FindRec.Name <> '.') and (FindRec.Name <> '..') then begin
          Target := AddBackslash(AppRoot) + FindRec.Name;
          DelTree(Target, True, True, True);
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function InitializeUninstall: Boolean;
var
  SrcCtl: String;
  ExitCode: Integer;
begin
  Result := False;
  UninstallCtlPath := '';
  SrcCtl := FindInstalledCtl;
  if SrcCtl = '' then begin
    Log('Cannot locate netswitchctl.exe under {app}.');
    SuppressibleMsgBox('Net Switch setup helper could not be found in ' + ExpandConstant('{app}') + '. Reinstall Net Switch to repair and uninstall.', mbError, MB_OK, IDOK);
    Exit;
  end;
  UninstallCtlPath := ExpandConstant('{tmp}\netswitchctl.exe');
  if not CopyFile(SrcCtl, UninstallCtlPath, False) then begin
    Log('Failed to copy netswitchctl.exe to {tmp}.');
    SuppressibleMsgBox('Net Switch could not prepare the uninstaller helper. No files have been removed.', mbError, MB_OK, IDOK);
    Exit;
  end;
  ExitCode := -1;
  if Exec(UninstallCtlPath, 'uninstall --app-dir "' + ExpandConstant('{app}') + '"',
    ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Result := ExitCode = 0;
  Log(Format('Net Switch uninstall stop/cleanup result: %d', [ExitCode]));
  if not Result then
    SuppressibleMsgBox('Net Switch could not be stopped. Retry uninstalling. No files have been removed.', mbError, MB_OK, IDOK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ExitCode: Integer;
begin
  { SuppressibleMsgBox takes its default answer during silent uninstall (/SILENT or /VERYSILENT). }
  if CurUninstallStep = usUninstall then begin
    DeleteMachineData := False;
    if SuppressibleMsgBox('Undo the Windows settings Net Switch changed (connection priority, keeping Wi-Fi on with the cable)?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON1, IDYES) = IDYES then begin
      ExitCode := -1;
      if (UninstallCtlPath <> '') and FileExists(UninstallCtlPath) and
         Exec(UninstallCtlPath, 'restore-windows', ExpandConstant('{tmp}'),
           SW_HIDE, ewWaitUntilTerminated, ExitCode) then
        DeleteMachineData := ExitCode = 0;
      Log(Format('Net Switch Windows restore result: %d', [ExitCode]));
      if not DeleteMachineData then
        SuppressibleMsgBox('Windows settings could not be fully restored. Your undo record is kept in ' +
          ExpandConstant('{commonappdata}\Net Switch') +
          '. Reinstall Net Switch to retry restoring them.', mbError, MB_OK, IDOK);
    end else begin
      DeleteMachineData := SuppressibleMsgBox('Delete the Windows undo record anyway? The current Windows settings will stay in place, and Net Switch will no longer be able to undo them.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
    end;
    RemoveManagedAppFiles;
  end;
  if CurUninstallStep = usPostUninstall then begin
    { Never delete the undo record after a failed restore. }
    if DeleteMachineData and (UninstallCtlPath <> '') and FileExists(UninstallCtlPath) then begin
      ExitCode := -1;
      Exec(UninstallCtlPath, 'cleanup-machine-data', ExpandConstant('{tmp}'),
        SW_HIDE, ewWaitUntilTerminated, ExitCode);
      Log(Format('Net Switch machine data cleanup result: %d', [ExitCode]));
      if (ExitCode <> 0) and DirExists(ExpandConstant('{commonappdata}\Net Switch')) then
        SuppressibleMsgBox('Some Net Switch machine data could not be deleted from ' + ExpandConstant('{commonappdata}\Net Switch') + '.', mbError, MB_OK, IDOK);
    end;
    { User settings and logs in AppData\Local\Net Switch are always retained. }
  end;
end;
