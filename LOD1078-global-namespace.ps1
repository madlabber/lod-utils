# Converts LOD environment to a global namespace demo lab

# How To Use:
# 1. Provision https://labondemand.netapp.com/node/1078
#    "Early Adopter Lab for Unified ONTAP 9.16.1 v1.0"
#
# 2. Start a new administrator powershell window
# 
# 3. Run this command:
#    iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/madlabber/lod-utils/refs/heads/main/LOD1078-global-namespace.ps1'))

# Define some vars:
# Cluster and SVM renames
$cluster1="NY_Cluster"
$cluster2="LA_Cluster"
$cluster3="DC_Cluster"
$svm1="svm1ny"
$svm1vol="NYFS"
$svm1dpvol="NYFS_backup"
$svm2="svm2la"
$svm3="svm3dc"
$svm3vol="DCFS"
$svm3dpvol="DCFS_backup"

#credentials
$clusteruser="admin"
$clusterpass="Netapp1!"
$domainuser="DEMO\Administrator"
$domainpass="Netapp1!"
$clustercred = New-Object System.Management.Automation.PSCredential $clusteruser,$(ConvertTo-SecureString -String $clusterpass -AsPlainText -Force)
$domaincred = New-Object System.Management.Automation.PSCredential $domainuser,$(ConvertTo-SecureString -String $domainpass -AsPlainText -Force)

# Configure Jumphost:
# Install Powershell modules:
write-host "# Install Powershell modules:"
if (-not (Get-Module -Name "NetApp.ONTAP" -ListAvailable)) {
    Write-Host "Module 'NetApp.ONTAP' not found. Installing..."
    write-host "# Accept the UAC prompt and do not close the popup window."
    Start-Process Powershell -Verb RunAs -wait -ArgumentList ' -command "Install-Module -Name NetApp.ONTAP" '
} 
Import-Module -Name NetApp.ONTAP

write-host "# install pstools"
Invoke-WebRequest -Uri https://download.sysinternals.com/files/PSTools.zip -Outfile C:\LOD\PSTools.zip
Expand-Archive -Path C:\LOD\PSTools.zip -DestinationPath C:\lod

Write-host "# install ssh-copy-id"
Invoke-WebRequest -Uri "https://github.com/maxshlain/ssh-copy-id-net/releases/download/v0.1.7/ssh-copy-id-net-0.1.7-win-x64.zip" -Outfile C:\LOD\ssh-copy-id-net-0.1.7-win-x64.zip
Expand-Archive -Path C:\LOD\ssh-copy-id-net-0.1.7-win-x64.zip -DestinationPath C:\LOD 

write-host "# Download files"
invoke-webrequest https://archive.org/download/paint.net-v5.0.13/paint.net.5.0.13.winmsi.x64.zip/paint.net.5.0.13.winmsi.x64.msi -outfile C:\LOD\paint.net.5.0.13.winmsi.x64.msi
Unblock-File -Path C:\LOD\paint.net.5.0.13.winmsi.x64.msi
Invoke-WebRequest https://upload.wikimedia.org/wikipedia/commons/thumb/a/a3/United_States_Capitol_west_front_edit2.jpg/1200px-United_States_Capitol_west_front_edit2.jpg -OutFile C:\LOD\wallpaper-dc.jpg
Unblock-File -Path C:\LOD\wallpaper-dc.jpg
invoke-webrequest https://upload.wikimedia.org/wikipedia/commons/thumb/7/7a/View_of_Empire_State_Building_from_Rockefeller_Center_New_York_City_dllu_%28cropped%29.jpg/2560px-View_of_Empire_State_Building_from_Rockefeller_Center_New_York_City_dllu_%28cropped%29.jpg -OutFile C:\LOD\wallpaper-ny.jpg
Unblock-File -Path C:\LOD\wallpaper-ny.jpg

write-host "# Copy files to other hosts"
copy-item C:\LOD\wallpaper-dc.jpg C:\LOD\wallpaper.jpg -tosession (new-pssession dc1)
copy-item C:\LOD\paint.net.5.0.13.winmsi.x64.msi C:\LOD\paint.net.5.0.13.winmsi.x64.msi -tosession (new-pssession dc1)
copy-item C:\LOD\wallpaper-ny.jpg C:\LOD\wallpaper.jpg -tosession (new-pssession win1)
copy-item C:\LOD\paint.net.5.0.13.winmsi.x64.msi C:\LOD\paint.net.5.0.13.winmsi.x64.msi -tosession (new-pssession win1)

# Configure Certificate Authentication
write-host "# Configure ssh key authentication"
mkdir C:\Users\Administrator.DEMO\.ssh
ssh-keygen -q -t ed25519 -f C:\Users\Administrator.DEMO\.ssh\id_ed25519 -N '""'

# RHEL1 is MIA
#start-process -FilePath "C:\LOD\ssh-copy-id-net.exe" -ArgumentList "linux1", "22", "root", "Netapp1!", "C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub" -Wait
#ssh -o "StrictHostKeyChecking=accept-new" -i C:\Users\Administrator.Demo\.ssh\id_ed25519 root@rhel1 cat /etc/rocky-release

# Add SSH keys to cluster1, cluster2, cluster3
write-host "# Add SSH keys to cluster1 and cluster 2"
Invoke-NcSsh -Controller "cluster1" -Credential $clustercred -Command "security login create -user-or-group-name admin -application ssh -authentication-method publickey -role admin"
Invoke-NcSsh -Controller "cluster1" -Credential $clustercred -Command "security login publickey create -username admin -application ssh -index 0 -publickey ""$(get-content C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub)"""
Invoke-NcSsh -Controller "cluster2" -Credential $clustercred -Command "security login create -user-or-group-name admin -application ssh -authentication-method publickey -role admin"
Invoke-NcSsh -Controller "cluster2" -Credential $clustercred -Command "security login publickey create -username admin -application ssh -index 0 -publickey ""$(get-content C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub)"""
Invoke-NcSsh -Controller "cluster3" -Credential $clustercred -Command "security login create -user-or-group-name admin -application ssh -authentication-method publickey -role admin"
Invoke-NcSsh -Controller "cluster3" -Credential $clustercred -Command "security login publickey create -username admin -application ssh -index 0 -publickey ""$(get-content C:\Users\Administrator.DEMO\.ssh\id_ed25519.pub)"""
sleep 30
ssh -o "StrictHostKeyChecking=accept-new" admin@cluster1 version
ssh -o "StrictHostKeyChecking=accept-new" admin@cluster2 version
ssh -o "StrictHostKeyChecking=accept-new" admin@cluster3 version

write-host "# Rename Clusters"
ssh admin@cluster1 cluster identity modify -name $cluster1
ssh admin@cluster2 cluster identity modify -name $cluster2
ssh admin@cluster3 cluster identity modify -name $cluster3

write-host "# Rename vServers"
ssh admin@cluster1 vserver rename -newname $svm1 -vserver svm1
ssh admin@cluster2 vserver rename -newname $svm2 -vserver svm2
ssh admin@cluster3 vserver rename -newname $svm3 -vserver svm3

write-host "# Enable 64bit identifiers"
ssh admin@cluster1 "set advanced; vserver nfs modify -vserver $svm1 -v3-64bit-identifiers enabled"
ssh admin@cluster2 "set advanced; vserver nfs modify -vserver $svm2 -v3-64bit-identifiers enabled"
ssh admin@cluster3 "set advanced; vserver nfs modify -vserver $svm3 -v3-64bit-identifiers enabled"

write-host "# Peer clusters"
ssh admin@cluster1 cluster peer policy modify -is-unauthenticated-access-permitted true
ssh admin@cluster1 cluster peer create -peer-addrs 192.168.0.125 -no-authentication true -initial-allowed-vserver-peers *
ssh admin@cluster1 sleep 30
ssh admin@cluster3 cluster peer policy modify -is-unauthenticated-access-permitted true
ssh admin@cluster3 cluster peer create -peer-addrs 192.168.0.121, 192.168.0.122 -no-authentication true -initial-allowed-vserver-peers *
ssh admin@cluster3 sleep 30

write-host "# Create vServer Peering"
ssh admin@cluster3 vserver peer create -vserver $svm3 -peer-cluster $cluster1 -peer-vserver $svm1 -applications flexcache snapmirror
ssh admin@cluster3 sleep 30
ssh admin@cluster1 vserver peer accept -vserver $svm1 -peer-vserver $svm3
ssh admin@cluster1 sleep 30

write-host "# Create Volumes on cluster1"
ssh admin@cluster1 vol create -volume Global -state online -policy default -unix-permissions ---rwxr-xr-x -type RW -snapdir-access true -snapshot-policy default -foreground true -tiering-policy none -analytics-state off -activity-tracking-state off -anti-ransomware-state disabled -granular-data disabled -snapshot-locking-enabled false -aggr-list cluster1_01_SSD_1 cluster1_02_SSD_1  -aggr-list-multiplier 4 -vserver $svm1 -space-guarantee none -size 50G -junction-path /Global
ssh admin@cluster1 vol create -volume $svm1vol -state online -policy default -unix-permissions ---rwxr-xr-x -type RW -snapdir-access true -snapshot-policy default -foreground true -tiering-policy none -analytics-state off -activity-tracking-state off -anti-ransomware-state disabled -granular-data disabled -snapshot-locking-enabled false -aggr-list cluster1_01_SSD_1 cluster1_02_SSD_1  -aggr-list-multiplier 4 -vserver $svm1 -space-guarantee none -size 50G -junction-path /Global/$svm1vol

write-host "# Create Volumes on cluster3"
ssh admin@cluster3 vol create -volume Global -state online -policy default -unix-permissions ---rwxr-xr-x -type RW -snapdir-access true -snapshot-policy default -foreground true -tiering-policy none -analytics-state off -activity-tracking-state off -anti-ransomware-state disabled -granular-data disabled -snapshot-locking-enabled false -aggr-list cluster3_01_SSD_1  -aggr-list-multiplier 4 -vserver $svm3 -space-guarantee none -size 50G -junction-path /Global
ssh admin@cluster3 vol create -volume $svm3vol -state online -policy default -unix-permissions ---rwxr-xr-x -type RW -snapdir-access true -snapshot-policy default -foreground true -tiering-policy none -analytics-state off -activity-tracking-state off -anti-ransomware-state disabled -granular-data disabled -snapshot-locking-enabled false -aggr-list cluster3_01_SSD_1  -aggr-list-multiplier 4 -vserver $svm3 -space-guarantee none -size 50G -junction-path /Global/$svm3vol

write-host "# Create Flexcaches"
ssh admin@cluster1 volume flexcache create -vserver $svm1 -volume $svm3vol -size 50G -origin-vserver $svm3 -origin-volume $svm3vol -junction-path /Global/$svm3vol
ssh admin@cluster3 volume flexcache create -vserver $svm3 -volume $svm1vol -size 50G -origin-vserver $svm1 -origin-volume $svm1vol -junction-path /Global/$svm1vol

write-host "# Create Snapmirror cluster3->cluster1"
ssh admin@cluster1 volume create -type dp -volume $svm3dpvol -state online -policy default -autosize-mode grow_shrink -snapdir-access true -aggr-list cluster1_01_SSD_1 -aggr-list-multiplier 4
ssh admin@cluster1 snapmirror create -source-path $svm3':'$svm3vol -destination-path $svm1':'$svm3dpvol -vserver $svm1 -policy Asynchronous
ssh admin@cluster1 snapmirror initialize -destination-path $svm1':'$svm3dpvol 
ssh admin@cluster1 sleep 90

write-host "# Create Snapmirror cluster1->cluster3"
ssh admin@cluster3 volume create -type dp -volume $svm1dpvol -state online -policy default -autosize-mode grow_shrink -snapdir-access true -aggr-list cluster3_01_SSD_1 -aggr-list-multiplier 8
ssh admin@cluster3 snapmirror create -source-path $svm1':'$svm1vol -destination-path $svm3':'$svm1dpvol -vserver $svm3 -policy Asynchronous
ssh admin@cluster3 snapmirror initialize -destination-path $svm3':'$svm1dpvol
ssh admin@cluster3 sleep 90

write-host "# Mount backup volume on cluster1:"
ssh admin@cluster1 volume mount $svm3dpvol -junction-path /$svm3dpvol 
ssh admin@cluster1 volume modify $svm3dpvol -snapdir-access true

write-host "# Mount backup volume on cluster3:"
ssh admin@cluster3 volume mount $svm1dpvol -junction-path /$svm1dpvol 
ssh admin@cluster3 volume modify $svm1dpvol -snapdir-access true

write-host "# Create Shares on cluster1"
ssh admin@cluster1 vserver cifs share create -share-name Global -path /Global -vserver $svm1
ssh admin@cluster1 vserver cifs share create -share-name $svm3dpvol -path /$svm3dpvol -vserver $svm1
ssh admin@cluster1 vserver cifs share properties add -share-name $svm3dpvol -share-properties showsnapshot

write-host "# Create Shares on cluster3"
ssh admin@cluster3 vserver cifs share create -share-name Global -path /Global -vserver $svm3
ssh admin@cluster3 vserver cifs share create -share-name $svm1dpvol -path /$svm1dpvol -vserver $svm3
ssh admin@cluster3 vserver cifs share properties add -share-name $svm1dpvol -share-properties showsnapshot

write-host "# Create Directories"
New-Item -Path "\\192.168.0.151\Global\$svm3vol\Conversation Nation" -ItemType Directory
New-Item -Path "\\192.168.0.151\Global\$svm3vol\Tech ONTAP" -ItemType Directory
New-Item -Path "\\192.168.0.151\Global\$svm3vol\The DC Dish" -ItemType Directory
New-Item -Path "\\192.168.0.151\Global\$svm3vol\Tools" -ItemType Directory
New-Item -Path "\\192.168.0.131\Global\$svm1vol\Nocturnal Nonsense" -ItemType Directory
New-Item -Path "\\192.168.0.131\Global\$svm1vol\The Daily Edit" -ItemType Directory
New-Item -Path "\\192.168.0.131\Global\$svm1vol\The Morning Blend" -ItemType Directory
New-Item -Path "\\192.168.0.131\Global\$svm1vol\Tools" -ItemType Directory

write-host "# Copy Files"
Copy-Item -Path "C:\LOD\wallpaper-dc.jpg" -Destination "\\192.168.0.151\Global\$svm3vol\The DC Dish\DC1.jpg"
Copy-Item -Path "C:\LOD\wallpaper-dc.jpg" -Destination "\\192.168.0.151\Global\$svm3vol\The DC Dish\DC2.jpg"
Copy-Item -Path "C:\LOD\wallpaper-dc.jpg" -Destination "\\192.168.0.151\Global\$svm3vol\The DC Dish\DC3.jpg"
Copy-Item -Path "C:\LOD\wallpaper-dc.jpg" -Destination "\\192.168.0.151\Global\$svm3vol\The DC Dish\DC4.jpg"
Copy-Item -Path "C:\LOD\wallpaper-dc.jpg" -Destination "\\192.168.0.151\Global\$svm3vol\The DC Dish\DC5.jpg"
Copy-Item -Path "C:\LOD\wallpaper-dc.jpg" -Destination "\\192.168.0.151\Global\$svm3vol\The DC Dish\DC6.jpg"
Copy-Item -Path "C:\LOD\wallpaper-ny.jpg" -Destination "\\192.168.0.131\Global\$svm1vol\The Daily Edit\NY1.jpg"
Copy-Item -Path "C:\LOD\wallpaper-ny.jpg" -Destination "\\192.168.0.131\Global\$svm1vol\The Daily Edit\NY2.jpg"
Copy-Item -Path "C:\LOD\wallpaper-ny.jpg" -Destination "\\192.168.0.131\Global\$svm1vol\The Daily Edit\NY3.jpg"
Copy-Item -Path "C:\LOD\wallpaper-ny.jpg" -Destination "\\192.168.0.131\Global\$svm1vol\The Daily Edit\NY4.jpg"
Copy-Item -Path "C:\LOD\wallpaper-ny.jpg" -Destination "\\192.168.0.131\Global\$svm1vol\The Daily Edit\NY5.jpg"
Copy-Item -Path "C:\LOD\wallpaper-ny.jpg" -Destination "\\192.168.0.131\Global\$svm1vol\The Daily Edit\NY6.jpg"

write-host "# Create Files"
New-Item -Path "\\192.168.0.131\Global\$svm1vol\The Daily Edit\Daily Edit Script Draft 1.txt"
New-Item -Path "\\192.168.0.131\Global\$svm1vol\The Daily Edit\Daily Edit Script Final.txt"
New-Item -Path "\\192.168.0.131\Global\$svm1vol\The Daily Edit\Daily Edit Script Final Final.txt"
New-Item -Path "\\192.168.0.131\Global\$svm1vol\The Daily Edit\Daily Edit Script Final Final Final.txt"

write-host "# Add drive leter on jumphost"
New-PSDrive -Name G -PSProvider FileSystem -Root "\\192.168.0.151\Global" -Persist

# write-host "# Extract demo files"
# Expand-Archive -Path ~\Downloads\files.zip -DestinationPath G:\

write-host "Configuring DC1..."

write-host "# Add DNS records"
invoke-command -ComputerName dc1 -Credential $domaincred -Command {
    # Add DNS record for NY1
    Add-DnsServerResourceRecordA -Name "NY1" -ZoneName "demo.netapp.com" -AllowUpdateAny -IPv4Address "192.168.0.40" 
}

write-host "# Set Wallpaper"
invoke-command -ComputerName dc1 -Credential $domaincred -Command {
    # Set the Wallpaper registry key to the image path
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'WallPaper' -Value C:\LOD\wallpaper.jpg

    # Set the WallpaperStyle (e.g., 2 for Stretch, 0 for Tile/Center, 6 for Fit, 10 for Fill)
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'WallpaperStyle' -Value 2

    # Refresh the user's desktop to apply the changes without rebooting
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters 1, True
}

write-host "# Enable show hidden items"
invoke-command -ComputerName dc1 -credential $domaincred -Command {
    # Enable show hidden items
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
}

write-host "# create startup script"
invoke-command -ComputerName dc1 -Credential $domaincred -Command {
    Param( $svm1dpvol )
    Add-Content -Path "C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mapdrives.bat" -Value "net use G: \\192.168.0.151\Global"
    Add-Content -Path "C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mapdrives.bat" -Value "net use Z: \\192.168.0.151\$svm1dpvol"
} -ArgumentList $svm1dpvol

write-host "# create runonce script"
invoke-command -ComputerName dc1 -Credential $domaincred -Command {
    Add-Content -Path 'C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runonce.bat' -Value "msiexec /i C:\LOD\paint.net.5.0.13.winmsi.x64.msi"
    Add-Content -Path 'C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runonce.bat' -Value 'del "C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runonce.bat"'
}

write-host "Configuring Win1..."

write-host "# Set wallpaper"
invoke-command -ComputerName win1 -credential $domaincred -Command {
    # Set the Wallpaper registry key to the image path
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'WallPaper' -Value C:\LOD\wallpaper.jpg

    # Set the WallpaperStyle (e.g., 2 for Stretch, 0 for Tile/Center, 6 for Fit, 10 for Fill)
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\' -Name 'WallpaperStyle' -Value 2

    # Refresh the user's desktop to apply the changes without rebooting
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters 1, True
}

write-host "# Enable show hidden items"
invoke-command -ComputerName win1 -credential $domaincred -Command {
    # Enable show hidden items
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
}

write-host "# create startup script"
invoke-command -ComputerName win1 -Credential $domaincred -Command {
    Param( $svm3dpvol )
    Add-Content -Path "C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mapdrives.bat" -Value "net use G: \\192.168.0.131\Global"
    Add-Content -Path "C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mapdrives.bat" -Value "net use Z: \\192.168.0.131\$svm3dpvol"
} -ArgumentList $svm3dpvol

write-host "# create runonce script"
invoke-command -ComputerName win1 -Credential $domaincred -Command {
    Add-Content -Path 'C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runonce.bat' -Value "msiexec /i C:\LOD\paint.net.5.0.13.winmsi.x64.msi"
    Add-Content -Path 'C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runonce.bat' -Value 'del "C:\Users\Administrator.DEMO\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\runonce.bat"'
}
