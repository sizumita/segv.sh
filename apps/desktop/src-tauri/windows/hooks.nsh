; Hooks of the Windows installer (bundle.windows.nsis.installerHooks in tauri.windows.conf.json).

; The uninstaller also removes the AppUserModelID that the app registers for its notifications (src/notify.rs).
!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Classes\AppUserModelId\sh.segv.desktop"
!macroend
