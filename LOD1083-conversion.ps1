# Converts LOD environment to generic vsphere on netapp:
# 4 hosts with 8 CPU / 24gb RAM each
# 2 NFS datastores of ~ 600gb each
# 1 ansible controller running Rocky 9.4
# VSCode desktop environment on the jumphost with plugins for ansible, powershell, and remote-ssh

# How To Use:
# 1. Provision https://labondemand.netapp.com/node/1083
#    "Easier Data Management with ONTAP Tools for VMware vSphere 10.2 v4.0"
#
# 2. Start a new administrator powershell window
# 
# 3. Run this command:
#    iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/madlabber/lod-utils/refs/heads/main/LOD1083-conversion.ps1'))


# Install VSCode and some plugins:
write-host "# Install VSCode and some plugins:"
Invoke-WebRequest -Uri "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64" -Outfile C:\LOD\VSCodeSetup-x64.exe
start-process -FilePath "C:\LOD\VSCodeSetup-x64.exe" -ArgumentList "/VERYSILENT", "/MERGETASKS=!runcode" -Wait
& 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension ms-vscode-remote.remote-ssh
& 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension ms-vscode.powershell
& 'C:\Program Files\Microsoft VS Code\bin\code' --install-extension redhat.ansible

# Install Powershell modules:
write-host "# Install Powershell modules:"
Install-Module -Name VCF.PowerCLI
Install-Module -Name NetApp.ONTAP
Import-Module -Name VMware.PowerCLI 
Import-Module -Name NetApp.ONTAP

# Configure clusters 
write-host "# Configure clusters "
$username = 'admin'
$password = ConvertTo-SecureString -String 'Netapp1!' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username,$password
Connect-NcController "cluster1" -Credential $credential
Invoke-NcSsh -Controller "cluster1" -Credential $credential -Command "vserver nfs modify -vstorage enabled"
$result = new-ncvol ISOs cluster1_01_SSD_1 100g /ISOs -vservercontext svm1 
$result = new-ncvol code cluster1_01_SSD_1 100g /code -vservercontext svm1
$result = new-ncvol vmnfs01 cluster1_01_SSD_1 600g /vmnfs01 -vservercontext svm1
Connect-NcController "cluster2" -Credential $credential
Invoke-NcSsh -Controller "cluster2" -Credential $credential -Command "vserver nfs modify -vstorage enabled"
$result = new-ncvol vmnfs02 cluster2_01_SSD_1 600g /vmnfs02 -vservercontext svm2

# Configure vSphere:
write-host "# Configure vSphere:"
Connect-VIServer -Server vc1.demo.netapp.com -user Administrator@demo.local -password Netapp1! -force
$result = add-vmhost esx3.demo.netapp.com -Location Cluster1 -user root -password NetApp123! -force 
$result = add-vmhost esx4.demo.netapp.com -Location Cluster1 -user root -password NetApp123! -force 
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name ISOs -Path /ISOs -NfsHost 192.168.0.132
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name vmnfs01 -Path /vmnfs01 -NfsHost 192.168.0.132
$result = Get-Cluster Cluster1 | Get-VMHost | New-Datastore -Nfs -Name vmnfs02 -Path /vmnfs02 -NfsHost 192.168.0.142

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

# Done with Powershell:
#exit

# TBD: 
# - install vaai 
# - Git clone
# - make this an invokable script

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
	

