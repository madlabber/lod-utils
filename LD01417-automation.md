# Automation Sandbox lab conversion script

## About
This script converts an existing LOD environment into an automation sandbox containing a vscode desktop, an ansible controller, 4 ESX hosts, and 2 ONTAP clusters.

## How To Use:
1. Provision ["ONTAP Tools for VMware vSphere 10.5 v5.1"](https://labondemand.netapp.com/node/1454)

2. Start a new Administrator powershell window

   Right click the Start button and select "Windows PowerShell (Admin)"

3. Copy this command and past it into the powershell window in your lab using the Edit->Paste option in your browser.
   ```
   iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/madlabber/lod-utils/refs/heads/main/LD01417-automation.ps1'))
   ```
