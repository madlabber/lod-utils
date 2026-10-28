# ONTAP Select Lab conversion script
## About
This script converts an existing Lab On Demand environment into an ONTAP Select lab on demand environment.  After conversion the lab can support 1,2, and 4 node ONTAP Select clusters, in HW Raid, SW Raid, and VNAS deployment scenarios.  

## How to use:
1. Provision ["ONTAP Tools for VMware vSphere 10.5 v5.1"](https://labondemand.netapp.com/node/1454)

2. Start a new Administrator powershell window
   Right click the Start button and select "Windows PowerShell (Admin)"

3. Copy this command and past it into the powershell window in your lab using the Edit->Paste option in your browser.
   ```
   iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/madlabber/lod-utils/refs/heads/main/LD01417-ontap-select.ps1'))
   ```

## Readme
note: this file will also be placed on the desktop by the script.

This conversion script prepares the lab environment for an ONTAP Select deployment, and creates the ONTAP Select Deploy VM, but does not add the hosts to deploy or create any ONTAP Select clusters.  You can use the standard out of the box workflows for adding hosts and creating cluster.

Suggested deployment plan:
1. Log in to ONTAP Select deploy at https://deploy.demo.netapp.com using the following credentials:
```
URL: [deploy](https://deploy.demo.netapp.com)
user: admin
password: Netapp1!
```

2. Add the first hosts as follows:
```
using vcenter: enabled
vcenter: vc1.demo.netapp.com
vcenter username: administrator@demo.local
vcenter password: Netapp1!
host: esx1.demo.netapp.com
```

3. Click add to add the following additional hosts
```
esx2.demo.netapp.com
esx3.demo.netapp.com
esx4.demo.netapp.com
```

4. Click Next to proceed to the cluster creation page.  From here you can create any combination of 1, 2 or 4 node clusters.


