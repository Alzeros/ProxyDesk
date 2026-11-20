' ProxyDesk launcher - starts the app window with no console flash.
Option Explicit
Dim sh, fso, here, py, cmd
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
py = sh.ExpandEnvironmentStrings("%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe")
If Not fso.FileExists(py) Then py = "pythonw.exe"
cmd = """" & py & """ """ & here & "\desk.py"""
sh.Run cmd, 0, False
