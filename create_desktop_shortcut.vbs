' Create a Desktop shortcut for ProxyDesk with its icon.
Option Explicit
Dim sh, fso, here, desktop, lnkPath, sc
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
desktop = sh.SpecialFolders("Desktop")
lnkPath = fso.BuildPath(desktop, "ProxyDesk.lnk")

Set sc = sh.CreateShortcut(lnkPath)
sc.TargetPath = sh.ExpandEnvironmentStrings("%SystemRoot%\System32\wscript.exe")
sc.Arguments = """" & fso.BuildPath(here, "launch_desk.vbs") & """"
sc.WorkingDirectory = here
sc.IconLocation = fso.BuildPath(here, "proxydesk.ico") & ",0"
sc.Description = "ProxyDesk"
sc.Save

MsgBox "Desktop shortcut created: " & lnkPath, vbInformation, "ProxyDesk"
