# Code Snippets
Here are some useful code snippets to run inside LOD

Unless otherwise specified, run these examples in an administrator powershell window

### Installing Visual Studio Code on the jumphost
```
Start-BitsTransfer -Source "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64" -Destination C:\LOD\VSCodeSetup-x64.exe
start-process -FilePath "C:\LOD\VSCodeSetup-x64.exe" -ArgumentList "/VERYSILENT", "/MERGETASKS=!runcode" -Wait
& 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension ms-vscode-remote.remote-ssh
& 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension ms-vscode.powershell
& 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension redhat.ansible
```

