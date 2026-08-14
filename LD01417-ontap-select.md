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

4. While this is running download the ONTAP Select Deploy VM from the mysupport site.  
   It can be found either in the products page or in the evaluations page, depending on your entitlements.

## Readme
note: this file will also be placed on the desktop by the script.

This conversion script prepares the lab environment for an ONTAP Select deployment, but does not perform the actual deployment.

You must download the ONTAP Select Deploy tool from mysupport.netapp.com either from the product downloads area or the evaluation downloads area.
Then you must install ONTAP Select Deploy, and add the available management servers and hosts to Deploys inventory. 
Then you can use the 4 available hosts to build any combination of 1,2 or 4 node clusters.

Suggested deployment plan:
1. Use the Deploy OVF feature on vc1.demo.netapp.com to install ONTAP Select Deploy on esx2 on datastore 'local2', with the following network parameters:
```
Hostname: deploy
Network: VM Network
ip_address: 192.168.0.99
Netmask: 255.255.255.0
Gateway: 192.168.0.1
DNS Server: 192.168.0.253
```

2. On the ONTAP Deploy Administration tab, add both vcenter servers to the Management Servers list
```
vc1.demo.netapp.com
vc2.demo.netapp.com
```

3. On the ONTAP Deploy Hypervisor Hosts tab, add the available ESX hosts.
```
management server: vc1.demo.netapp.com
hosts: esx1.demo.netapp.com
       esx2.demo.netapp.com

management server: vc2.demo.netapp.com
hosts: esx3.demo.netapp.com
       esx4.demo.netapp.com
```

4. Deploy a single node OTS cluster to esx1.demo.netapp.com on storage pool "VMFS1"

5. Deploy a 2 node OTS cluster to esx3 and esx4, using storage pools "VMFS3" and "VMFS4"

### Notes 
Note that a 2 or 4 node HA deployment will need some networking remediation because this lab only has one network.
This causes incorrect broadcast domain and port assignments during HA bringup that may need manual remediation.

example commands (for a 2-node cluster named 'demo2'):
```
  broadcast-domain remove-ports -broadcast-domain Cluster -ipspace Cluster -ports demo2-01:e0b,demo2-01:e0g
  broadcast-domain add-ports -broadcast-domain Default -ports demo2-01:e0b,demo2-01:e0g
  broadcast-domain add-ports -broadcast-domain Default -ports demo2-02:e0b,demo2-02:e0g
  network interface modify -vserver demo2 -lif demo2-02_mgmt1 -home-port e0b
  network interface revert *
  broadcast-domain add-ports -broadcast-domain Default -ports demo2-02:e0a
  network interface modify -vserver demo2 -lif demo2-02_mgmt1 -home-port e0a
  network interface revert *
```
