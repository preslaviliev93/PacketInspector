; Extra installer steps, picked up automatically by electron-builder.
;
; 1. When the installer starts and Packet Inspector is already installed, it
;    doesn't just install a second time. It says what is installed and offers:
;      same version   -> Uninstall, or close
;      older version  -> Update, Uninstall, or close
;      newer version  -> Uninstall, or close
;    Silent installs (/S) skip the question, so scripted upgrades keep working.
; 2. Adds an "Uninstall Packet Inspector" entry to the Start menu.

!ifndef BUILD_UNINSTALLER

; Compare dotted versions. In: $R0 = installed, $R1 = this installer.
; Out: $R2 = 0 same, 1 installed is newer, 2 installed is older.
Function piCompareVersions
  Push $R3
  Push $R4
  Push $R5
  Push $R6
  StrCpy $R2 0
  StrCpy $R5 0 ; component counter
  next_component:
    IntCmp $R5 4 cmp_done
    ; take the next number from $R0 into $R3 and from $R1 into $R4
    StrCpy $R6 $R0
    Call piTakeNumber
    StrCpy $R3 $R6
    StrCpy $R0 $R7
    StrCpy $R6 $R1
    Call piTakeNumber
    StrCpy $R4 $R6
    StrCpy $R1 $R7
    IntCmp $R3 $R4 same_component installed_older installed_newer
  same_component:
    IntOp $R5 $R5 + 1
    Goto next_component
  installed_older:
    StrCpy $R2 2
    Goto cmp_done
  installed_newer:
    StrCpy $R2 1
  cmp_done:
  Pop $R6
  Pop $R5
  Pop $R4
  Pop $R3
FunctionEnd

; In: $R6 = "1.0.3-beta". Out: $R6 = 1 (leading number), $R7 = rest after the first dot.
Function piTakeNumber
  Push $R8
  Push $R9
  StrCpy $R8 0
  find_dot:
    StrCpy $R9 $R6 1 $R8
    StrCmp $R9 "" no_dot
    StrCmp $R9 "." got_dot
    IntOp $R8 $R8 + 1
    Goto find_dot
  got_dot:
    IntOp $R9 $R8 + 1
    StrCpy $R7 $R6 "" $R9
    StrCpy $R6 $R6 $R8
    Goto to_int
  no_dot:
    StrCpy $R7 ""
  to_int:
    IntOp $R6 $R6 + 0
  Pop $R9
  Pop $R8
FunctionEnd

; In: $R9 = UninstallString such as "C:\...\Uninstall Packet Inspector.exe" /allusers
; Launches it (ShellExecute, so Windows can elevate it) and leaves the installer.
Function piRunUninstaller
  StrCpy $R3 $R9 1
  StrCmp $R3 '"' quoted unquoted
  quoted:
    StrCpy $R4 1
    find_quote:
      StrCpy $R3 $R9 1 $R4
      StrCmp $R3 '"' found_quote
      StrCmp $R3 "" found_quote
      IntOp $R4 $R4 + 1
      Goto find_quote
    found_quote:
      IntOp $R5 $R4 - 1
      StrCpy $R6 $R9 $R5 1
      IntOp $R4 $R4 + 1
      StrCpy $R7 $R9 "" $R4
      Goto launch
  unquoted:
    StrCpy $R6 $R9
    StrCpy $R7 ""
  launch:
    IfFileExists "$R6" +3
      MessageBox MB_OK|MB_ICONEXCLAMATION "The uninstaller could not be found at:$\r$\n$R6$\r$\n$\r$\nRemove ${PRODUCT_NAME} from Settings > Apps instead."
      Return
    ExecShell "open" "$R6" "$R7"
FunctionEnd

!endif

!macro customInit
  ${IfNot} ${Silent}
  ${AndIfNot} ${UAC_IsInnerInstance}
    ; Look for an existing installation: just-for-me first, then for-everyone.
    ReadRegStr $R9 HKCU "${UNINSTALL_REGISTRY_KEY}" "UninstallString"
    ReadRegStr $R8 HKCU "${UNINSTALL_REGISTRY_KEY}" "DisplayVersion"
    ${If} $R9 == ""
      ReadRegStr $R9 HKLM "${UNINSTALL_REGISTRY_KEY}" "UninstallString"
      ReadRegStr $R8 HKLM "${UNINSTALL_REGISTRY_KEY}" "DisplayVersion"
    ${EndIf}

    ${If} $R9 != ""
      StrCpy $R0 $R8
      StrCpy $R1 "${VERSION}"
      Call piCompareVersions
      ${If} $R2 == 0
        MessageBox MB_YESNO|MB_ICONQUESTION "${PRODUCT_NAME} ${VERSION} is already installed on this computer.$\r$\n$\r$\nDo you want to uninstall it?$\r$\n$\r$\nYes - uninstall ${PRODUCT_NAME}$\r$\nNo - close this window" IDYES pi_uninstall
        Quit
      ${ElseIf} $R2 == 2
        MessageBox MB_YESNOCANCEL|MB_ICONQUESTION "${PRODUCT_NAME} $R8 is installed on this computer.$\r$\n$\r$\nYes - update it to version ${VERSION} (your settings are kept)$\r$\nNo - uninstall ${PRODUCT_NAME} $R8$\r$\nCancel - close this window" IDYES pi_continue IDNO pi_uninstall
        Quit
      ${Else}
        MessageBox MB_YESNO|MB_ICONQUESTION "A newer version of ${PRODUCT_NAME} ($R8) is already installed. This installer contains the older version ${VERSION}.$\r$\n$\r$\nDo you want to uninstall the installed version?$\r$\n$\r$\nYes - uninstall ${PRODUCT_NAME} $R8$\r$\nNo - close this window" IDYES pi_uninstall
        Quit
      ${EndIf}
      pi_uninstall:
        Call piRunUninstaller
        Quit
      pi_continue:
    ${EndIf}
  ${EndIf}
!macroend

!define PI_FW_RULE "Packet Inspector - MikroTik stream (UDP 37008)"

!macro customInstall
  CreateShortCut "$SMPROGRAMS\Uninstall ${PRODUCT_NAME}.lnk" "$INSTDIR\${UNINSTALL_FILENAME}" "" "$INSTDIR\${UNINSTALL_FILENAME}" 0 SW_SHOWNORMAL "" "Remove ${PRODUCT_NAME} from this computer"
  ; Settings > Apps shows the app's own icon (the uninstaller has a "remove" badge).
  WriteRegStr SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXECUTABLE_FILENAME},0"
  ; Installing for everyone runs with administrator rights, so allow the MikroTik
  ; stream (inbound UDP 37008) through Windows Firewall now. Per-user installs
  ; can't; the app offers a one-click "Allow through firewall" instead.
  ${If} ${UAC_IsAdmin}
    nsExec::Exec 'netsh advfirewall firewall delete rule name="${PI_FW_RULE}"'
    Pop $0
    nsExec::Exec 'netsh advfirewall firewall add rule name="${PI_FW_RULE}" dir=in action=allow protocol=UDP localport=37008 profile=any'
    Pop $0
  ${EndIf}
!macroend

!macro customUnInstall
  Delete "$SMPROGRAMS\Uninstall ${PRODUCT_NAME}.lnk"
  ${If} ${UAC_IsAdmin}
  ${AndIfNot} ${isUpdated}
    nsExec::Exec 'netsh advfirewall firewall delete rule name="${PI_FW_RULE}"'
    Pop $0
  ${EndIf}
  ; The main removal leaves the (now empty) install folder behind, because the
  ; uninstaller's own working directory is that folder and Windows won't delete
  ; a directory a running process is "standing in". Step out, then remove it.
  ; Plain RMDir only succeeds if the folder is empty, so nothing else is at risk.
  SetOutPath "$TEMP"
  RMDir "$INSTDIR"
!macroend
