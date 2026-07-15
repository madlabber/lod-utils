# How To Use:
# 1. Provision https://labondemand.netapp.com/node/1454
#    "ONTAP Tools for VMware vSphere 10.5 v5.1"
#
# 2. Start a new administrator powershell window
# 
# 3. Run this command:
#    iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/madlabber/lod-utils/refs/heads/main/LD01417-ontap-select.ps1'))

# What it does:
# Converts LOD environment to an ONTAP Select on VMware lab environment.
# Note while this prepares the environment for an OTS deployment, it does not
# download the ONTAP Select deploy image.  You must download that within the lab from the MySupport site.

# To Do:
# - Add DNS records for deploy
# - clone the ansible project on linux1

# Install VSCode and some plugins:
# write-host "# Install VSCode and some plugins:"
# Invoke-WebRequest -Uri "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64" -Outfile C:\LOD\VSCodeSetup-x64.exe
# start-process -FilePath "C:\LOD\VSCodeSetup-x64.exe" -ArgumentList "/VERYSILENT", "/MERGETASKS=!runcode" -Wait
# & 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension ms-vscode-remote.remote-ssh
# & 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension ms-vscode.powershell
# & 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension redhat.ansible

# Make space for powershell status bar
write-host "#"
write-host "#"
write-host "#"
write-host "#"
write-host "#"
write-host "#"

# Install Powershell modules:
write-host "# Install Powershell modules:"
write-host "# this will take several minutes..."
write-host "- VCF.PowerCLI"
Install-Module -Name VCF.PowerCLI -AllowClobber -Force
write-host "- NetApp.ONTAP"
Install-Module -Name NetApp.ONTAP
Import-Module -Name VMware.PowerCLI 
Import-Module -Name NetApp.ONTAP

# Configure clusters 
write-host "# Configure clusters "
write-host "- cluster1"
$username = 'admin'
$password = ConvertTo-SecureString -String 'Netapp1!' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username,$password
Connect-NcController "cluster1" -Credential $credential
Invoke-NcSsh -Controller "cluster1" -Credential $credential -Command "vserver nfs modify -vstorage enabled"
$result = new-ncvol ISOs cluster1_01_SSD_1 100g /ISOs -vservercontext svm1 
$result = new-ncvol code cluster1_01_SSD_1 100g /code -vservercontext svm1
$result = new-ncvol pool1 cluster1_01_SSD_1 3000g /pool1 -vservercontext svm1
$result = new-ncvol pool3 cluster1_01_SSD_1 3000g /pool3 -vservercontext svm1
write-host "- cluster1"
Connect-NcController "cluster2" -Credential $credential
Invoke-NcSsh -Controller "cluster2" -Credential $credential -Command "vserver nfs modify -vstorage enabled"
$result = new-ncvol pool2 cluster2_01_SSD_1 3000g /pool2 -vservercontext svm2
$result = new-ncvol pool4 cluster2_01_SSD_1 3000g /pool4 -vservercontext svm2

# Setup SSH keys for linux1
write-host "# Setup SSH keys for linux1"
mkdir C:\Users\Administrator.DEMO\.ssh
ssh-keygen -q -t ed25519 -f C:\Users\Administrator.DEMO\.ssh\id_ed25519 -N '""'
Invoke-WebRequest -Uri "https://github.com/maxshlain/ssh-copy-id-net/releases/download/v0.1.7/ssh-copy-id-net-0.1.7-win-x64.zip" -Outfile C:\LOD\ssh-copy-id-net-0.1.7-win-x64.zip
Expand-Archive -Path C:\LOD\ssh-copy-id-net-0.1.7-win-x64.zip -DestinationPath C:\LOD 
start-process -FilePath "C:\LOD\ssh-copy-id-net.exe" -ArgumentList "linux1", "22", "root", "Netapp1!", "C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub" -Wait
ssh -o "StrictHostKeyChecking=accept-new" -i C:\Users\Administrator.Demo\.ssh\id_ed25519 root@linux1 cat /etc/rocky-release

# Add SSH keys to cluster1 and cluster 2
write-host "# Add SSH keys to cluster1 and cluster 2"
Invoke-NcSsh -Controller "cluster1" -Credential $credential -Command "security login create -user-or-group-name admin -application ssh -authentication-method publickey -role admin"
Invoke-NcSsh -Controller "cluster1" -Credential $credential -Command "security login publickey create -username admin -application ssh -index 0 -publickey ""$(get-content C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub)"""
Invoke-NcSsh -Controller "cluster2" -Credential $credential -Command "security login create -user-or-group-name admin -application ssh -authentication-method publickey -role admin"
Invoke-NcSsh -Controller "cluster2" -Credential $credential -Command "security login publickey create -username admin -application ssh -index 0 -publickey ""$(get-content C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub)"""
sleep 30
ssh -o "StrictHostKeyChecking=accept-new" admin@cluster1 version
ssh -o "StrictHostKeyChecking=accept-new" admin@cluster2 version

# Configure Linux1 
write-host "# Configure Linux1 "
ssh root@linux1 dnf install -y epel-release
ssh root@linux1 dnf install -y nfs-utils git mtools qemu-img ansible python3-pip
ssh root@linux1 pip3 install --upgrade pip 
ssh root@linux1 pip3 install netapp-lib pyvmomi pywinrm pycdlib 
ssh root@linux1 mkdir /root/code
ssh root@linux1 mount -t nfs 192.168.0.132:/code /root/code

# Configure Cluster1 for max capacity
write-host "# Configure Cluster1 for max capacity"
ssh admin@cluster1 aggr modify * -raidtype raid4
ssh admin@cluster1 aggr modify * -maxraidsize 14
ssh admin@cluster1 vol move start * cluster1_01_SSD_1 -foreground true
ssh admin@cluster1 aggr delete cluster1_02_SSD_1
ssh admin@cluster1 aggr add-disks -aggregate cluster1_01_SSD_1 -diskcount 2 -raidgroup rg0
ssh admin@cluster1 aggr relocation start -node cluster1-01 -destination cluster1-02 -aggregate-list cluster1_01_SSD_1
ssh admin@cluster1 sleep 30
ssh admin@cluster1 aggr add-disks -aggregate cluster1_01_SSD_1 -diskcount 14 
ssh admin@cluster1 aggr relocation start -node cluster1-02 -destination cluster1-01 -aggregate-list cluster1_01_SSD_1

# Configure Cluster2 for max capacity
write-host "# Configure Cluster1 for max capacity"
ssh admin@cluster2 aggr modify * -raidtype raid4
ssh admin@cluster2 aggr modify * -maxraidsize 14
ssh admin@cluster2 vol move start * cluster2_01_SSD_1 -foreground true
ssh admin@cluster2 aggr delete cluster2_02_SSD_1
ssh admin@cluster2 aggr add-disks -aggregate cluster2_01_SSD_1 -diskcount 2 -raidgroup rg0
ssh admin@cluster2 aggr relocation start -node cluster2-01 -destination cluster2-02 -aggregate-list cluster2_01_SSD_1
ssh admin@cluster2 sleep 30
ssh admin@cluster2 aggr add-disks -aggregate cluster2_01_SSD_1 -diskcount 14
ssh admin@cluster2 aggr relocation start -node cluster2-02 -destination cluster2-01 -aggregate-list cluster2_01_SSD_1

# Set space reporting to logical
write-host "# Configure logical space reporting"
ssh admin@cluster1 volume modify pool1 -is-space-reporting-logical true
ssh admin@cluster1 volume modify pool3 -is-space-reporting-logical true
ssh admin@cluster2 volume modify pool2 -is-space-reporting-logical true
ssh admin@cluster2 volume modify pool4 -is-space-reporting-logical true

# Configure vSphere:
write-host "# Configure vSphere:"
Connect-VIServer -Server vc1.demo.netapp.com -user Administrator@demo.local -password Netapp1! -force
Connect-VIServer -Server vc2.demo.netapp.com -user Administrator@demo.local -password Netapp1! -force
# $result = add-vmhost esx2.demo.netapp.com -Server vc2.demo.netapp.com -Location Cluster1 -user root -password NetApp123! -force 
# $result = remove-vmhost esx2.demo.netapp.com -Server vc1.demo.netapp.com -Confirm:$false
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name ISOs -Path /ISOs -NfsHost 192.168.0.132
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name pool1 -Path /pool1 -NfsHost 192.168.0.132
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name pool2 -Path /pool2 -NfsHost 192.168.0.142
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name pool3 -Path /pool3 -NfsHost 192.168.0.132
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name pool4 -Path /pool4 -NfsHost 192.168.0.142

# Add Portgroup for HA
Get-Cluster -Name "Cluster1" | Get-VMHost | Get-VirtualSwitch -Name "vSwitch0" | New-VirtualPortGroup -Name "OTS-Internal" 

# Stop the OTV VM
Stop-VM -VM "OTV1" -Confirm:$false

# Add some documentation to the desktop
$IPAddresses = @"
#IP Address Map:
# 192.168.0.1	    Gateway
# 192.168.0.5	    Jumphost
# 192.168.0.10	AE (LOD Automation Engine, Ubuntu host with powershell for linux)
# 192.168.0.31	vc1
# 192.168.0.32	vc2
# 192.168.0.51	esx1
# 192.168.0.52	Esx2
# 192.168.0.53	Esx3
# 192.168.0.54	Esx4
# 192.168.0.61	Linux1 (nested)
# 192.168.0.62	OTV1
# 192.168.0.64	Linux2 (nested)
# 192.168.0.99  Deploy
# 192.168.0.101	[cluster1] cluster_mgmt
# 192.168.0.102	[cluster2] cluster_mgmt
# 192.168.0.111	cluster1_01_mgmt1
# 192.168.0.112	cluster1_02_mgmt1
# 192.168.0.113	cluster2_01_mgmt1
# 192.168.0.114	cluster2_02_mgmt1
# 192.168.0.121	[cluster1] ic_1
# 192.168.0.122	[cluster1] ic_2
# 192.168.0.123	[cluster2] ic_1
# 192.168.0.124	[cluster2] ic_2
# 192.168.0.131	[svm1] nfs_1
# 192.168.0.132	[svm1] nfs_2
# 192.168.0.133	[svm1] iscsi_1
# 192.168.0.134	[svm1] iscsi_2
# 192.168.0.135	[svm1] nvme_1
# 192.168.0.136	[svm1] nvme_2
# 192.168.0.141	[svm2] nfs_1
# 192.168.0.142	[svm2] nfs_2
# 192.168.0.143	[svm2] iscsi_1
# 192.168.0.144	[svm2] iscsi_2
# 192.168.0.145	[svm2] nvme_1
# 192.168.0.146	[svm2] nvme_2

"@

$IPAddresses | Out-File -FilePath "C:\Users\Administrator.DEMO\Desktop\IPAddresses.txt"

$Readme = @"
This conversion prepares tthe lab environment for an ONTAP Select deployment, but does not perform the actual deployment.

You must download the ONTAP Select Deploy tool from mysupport.netapp.com either from the product downloads area or the evaluation downloads area.

Suggested deployment plan:
1. Use the Deploy OVF feature on vc1.demo.netapp.com to install ONTAP Select Deploy on esx1 on datastore 'local1', with the following network parameters:
    Hostname: deploy
    ip_address: 192.168.0.99
    Netmask: 255.255.255.0
    Gateway: 192.168.0.1
    DNS Server: 192.168.0.253

2. On the ONTAP Deploy Administration tab, add both vcenter servers to the Management Servers list
    vc1.demo.netapp.com
	vc2.demo.netapp.com

3. On the ONTAP Deploy Hypervisor Hosts tab, add the available ESX hosts.
   management server: vc1.demo.netapp.com
   hosts: esx1.demo.netapp.com
	      esx2.demo.netapp.com
   management server: vc2.demo.netapp.com
   hosts: esx3.demo.netapp.com
	      esx4.demo.netapp.com
		  
4. Deploy a single node OTS cluster to esx2.demo.netapp.com on storage pool "pool2"

5. Deploy a 2 node OTS cluster to esx3 and esx4, using storage pools "pool3" and "pool4"
Note that a 2 node HA deployment will need some networking remediation because this lab only has one network.
This causes incorrect broadcast domain and port assignments during HA bringup that may need manual remediation.


"@

$Readme | Out-File -FilePath "C:\Users\Administrator.DEMO\Desktop\README.TXT"

