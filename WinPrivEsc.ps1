function Get-situationalAwareness{
    Write-Host "`n[*] ---1. SITUATIONAL AWARENESS---" -ForegroundColor Cyan

    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    [PSCustomObject]@{
        Hostname    =   $cs.Name
        os          =   $os.Caption
        Build       =   $os.BuildNumber
        Architecture=   $os.OSArchitecture
        Domain      =   $cs.Domain
        LastBoot    =   $os.LastBootUpTime
    } | Format-List

    Write-Host "[*] Checking Interesting Environment Variables..." -ForegroundColor yellow
    Get-ChildItem Env: | Where-Object {$_.Name -match "(?i)AWS|API|KEY|PASS|SECRET|TOKEN|AUTH|AZURE|GITHUB"}
}

function Get-UserPrivAnalysis {
    Write-Host "`n[*]---2. USER & PRIVILEGE ANALYSIS ---" -ForegroundColor Cyan

    $privs = whoami /priv /fo csv | ConvertFrom-csv
    $DangerousPrivs = @("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege")

    foreach ($p in $privs){
        if ($DangerousPrivs -contains $p."Privilege Name" -and $p.state -eq "Enabled"){
            Write-Host "[!]Found dangerous privilege ENABLED: $($p.'Privilege Name')" -ForegroundColor Red
        }
        if ($DangerousPrivs -contains $p."Privilege Name" -and $p.state -eq "Disabled"){
            Write-Host "[!]Found dangerous privilege DISABLED: $($p.'Privilege Name')" -ForegroundColor Red
        }
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = $identity.Groups | ForEach-Object {$_.Translate([System.Security.Principal.NTAccount]) }

    $targetGroups = @("BUILTIN\Administrators", "Hyper-V Administrators", "DnsAdmins", "Print Operators", "BUILTIN\Backup Operators", "BUILTIN\Remote Desktop Users", "NT AUTHORITY\SYSTEM", "Enterprise Admins", "Domain Admins")

    foreach ($g in $groups){
        if ($targetGroups -contains $g.Value) {
            Write-Host "[!] HIGH VALUE: User is member of $($g.Value)" -Foregroundcolor Red
        }
    }
}

function Get-VulnerableServices {
    Write-Host "`n[*] --- 3.Service Audit---" -ForegroundColor Cyan
    
    $services = Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.State -eq 'Running'}

    foreach ($service in $services){
        $path = $service.PathName

        if ($path -match '^"?([a-zA-Z]:\\[^"]+\.exe)"?'){
            $binaryPath = $matches[1]
        }
        else{
            $binaryPath = $path.Split(" ")[0]
        }
        if ($binaryPath -match 'svchost\.exe$') {
            continue
            }
        if ($path -notmatch '^"' -and $path -match ' ' -and $path -notmatch '(?i)\\Windows\\system32\\'){
            Write-Host "[!] Unquoted Service path found: $($service.Name)" -ForegroundColor Red
            Write-Host "    Path: $path" -ForegroundColor Gray
        }
        if (Test-Path $binaryPath){
            try{
                $acl = Get-Acl $binaryPath
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

                foreach ($access in $acl.Access){
                    if (($access.IdentityReference -eq $currentUser -or $access.IdentityReference -match "Users") -and
                        ($access.FileSystemRights -match "Write|FullControl|Modify")){
                            Write-Host "[!] Weak permissions on Service Binary: $($access.FileSystemRights)" -ForegroundColor Gray
                            Write-Host "    Identity: $($access.IdentityReference)"
                        }
                }
                $dir = Split-Path $binaryPath

                if (Test-Path $dir){
                    $dirAcl = Get-Acl $dir

                    foreach($access in $dirAcl.Access){
                        if(
                            ($access.IdentityReference -eq $currentUser -or $access.IdentityReference -match "Users") -and 
                            ($access.FileSystemRights -match "Write|Modify|FullControl")
                        ){
                            Write-Host "[!] WRITABLE SERVICE DIRECTORY FOUND" -ForegroundColor Red
                            Write-Host "     Service : $($service.Name)"
                            Write-Host "     Path    : $dir"
                            Write-Host "     Identity: $($access.IdentityReference)"
                            Write-Host "     Rights  : $($access.FileSystemRights)"
                        }
                    }
                }
            } catch {
                #Access Denied to read ACL, most probably secure enough
            }
        }
    }
}

Write-Host "Starting priv esc audit..." -ForegroundColor Green
Get-situationalAwareness
Get-UserPrivAnalysis
Get-VulnerableServices
Write-Host "`n Enumeration Complete" -ForegroundColor Green
