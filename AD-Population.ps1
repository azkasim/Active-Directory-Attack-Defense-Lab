<#
.SYNOPSIS
    Populates an Active Directory lab domain with a realistic fake corporate
    structure: departments, security groups, ~40 random users, admin accounts,
    and a couple of deliberately weak accounts for attack/defense practice.

.NOTES
    Run this AS DOMAIN ADMIN on the domain controller itself (or any machine
    with RSAT + the ActiveDirectory PowerShell module), inside PowerShell
    (not PowerShell ISE necessarily, either is fine).

    This is for an isolated home lab only. Don't point this at anything real.
#>

Import-Module ActiveDirectory

# ---- CONFIG ---------------------------------------------------------------

$DomainDN   = (Get-ADDomain).DistinguishedName      # e.g. DC=lab,DC=local
$CompanyOU  = "Contoso"                             # fake company name
$DefaultPW  = "Passw0rd123!"                         # weak on purpose - lab only

$Departments = @(
    "Executive",
    "IT",
    "Finance",
    "HR",
    "Sales",
    "Marketing"
)

$FirstNames = @("James","Mary","John","Patricia","Robert","Jennifer","Michael","Linda",
                "William","Elizabeth","David","Barbara","Richard","Susan","Joseph","Jessica",
                "Thomas","Sarah","Charles","Karen","Daniel","Nancy","Matthew","Lisa",
                "Anthony","Betty","Mark","Margaret","Paul","Sandra")

$LastNames  = @("Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis",
                "Rodriguez","Martinez","Hernandez","Lopez","Gonzalez","Wilson","Anderson",
                "Thomas","Taylor","Moore","Jackson","Martin","Lee","Perez","Thompson",
                "White","Harris","Sanchez","Clark","Ramirez","Lewis","Robinson")

# ---- BUILD OU STRUCTURE -----------------------------------------------------

Write-Host "Creating base company OU: $CompanyOU" -ForegroundColor Cyan
New-ADOrganizationalUnit -Name $CompanyOU -Path $DomainDN -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue

$CompanyOUPath = "OU=$CompanyOU,$DomainDN"

New-ADOrganizationalUnit -Name "Groups" -Path $CompanyOUPath -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
New-ADOrganizationalUnit -Name "ServiceAccounts" -Path $CompanyOUPath -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue

foreach ($dept in $Departments) {
    Write-Host "Creating OU for department: $dept" -ForegroundColor Cyan
    New-ADOrganizationalUnit -Name $dept -Path $CompanyOUPath -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
}

# ---- CREATE SECURITY GROUPS -------------------------------------------------

$GroupsOUPath = "OU=Groups,$CompanyOUPath"

$Groups = @(
    @{ Name = "IT-Admins";          Desc = "Full IT department admin rights" },
    @{ Name = "Finance-Managers";   Desc = "Finance dept managers - access to shared finance folders" },
    @{ Name = "HR-Staff";           Desc = "HR staff - access to HR shares" },
    @{ Name = "Sales-Team";         Desc = "Sales staff" },
    @{ Name = "Marketing-Team";     Desc = "Marketing staff" },
    @{ Name = "Executive-Team";     Desc = "C-suite / executives" },
    @{ Name = "Helpdesk-L1";        Desc = "Tier 1 helpdesk - limited reset rights" },
    @{ Name = "All-Employees";      Desc = "Every user in the company" },
    @{ Name = "VPN-Users";          Desc = "Users permitted VPN access" }
)

foreach ($g in $Groups) {
    Write-Host "Creating group: $($g.Name)" -ForegroundColor Cyan
    New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security `
        -Path $GroupsOUPath -Description $g.Desc -ErrorAction SilentlyContinue
}

# ---- CREATE RANDOM USERS PER DEPARTMENT ------------------------------------

$AllUsers = @()

function New-RandomUser {
    param($First, $Last, $Dept, $OUPath, $Title, $ExtraGroups = @())

    $sam = ("{0}.{1}" -f $First, $Last).ToLower()
    $sam = $sam.Substring(0, [Math]::Min(20, $sam.Length))   # sAMAccountName length limit
    $upn = "$sam@$((Get-ADDomain).DNSRoot)"

    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        $sam = $sam + (Get-Random -Minimum 1 -Maximum 999)
        $upn = "$sam@$((Get-ADDomain).DNSRoot)"
    }

    New-ADUser -Name "$First $Last" `
        -GivenName $First -Surname $Last `
        -SamAccountName $sam -UserPrincipalName $upn `
        -Path $OUPath -Department $Dept -Title $Title `
        -AccountPassword (ConvertTo-SecureString $DefaultPW -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false `
        -ErrorAction SilentlyContinue

    Add-ADGroupMember -Identity "All-Employees" -Members $sam -ErrorAction SilentlyContinue
    foreach ($grp in $ExtraGroups) {
        Add-ADGroupMember -Identity $grp -Members $sam -ErrorAction SilentlyContinue
    }

    return $sam
}

$titlesByDept = @{
    "Executive" = @("CEO","CFO","COO","VP of Operations")
    "IT"        = @("IT Manager","Systems Administrator","Help Desk Technician","Network Engineer","IT Support")
    "Finance"   = @("Finance Manager","Accountant","Payroll Specialist","Financial Analyst")
    "HR"        = @("HR Manager","HR Coordinator","Recruiter")
    "Sales"     = @("Sales Manager","Account Executive","Sales Rep")
    "Marketing" = @("Marketing Manager","Content Specialist","Marketing Coordinator")
}

$groupByDept = @{
    "Executive" = @("Executive-Team","VPN-Users")
    "IT"        = @("IT-Admins","Helpdesk-L1","VPN-Users")
    "Finance"   = @("Finance-Managers","VPN-Users")
    "HR"        = @("HR-Staff")
    "Sales"     = @("Sales-Team","VPN-Users")
    "Marketing" = @("Marketing-Team")
}

$usedNames = @{}

foreach ($dept in $Departments) {
    $deptOUPath = "OU=$dept,$CompanyOUPath"
    $countForDept = Get-Random -Minimum 4 -Maximum 8   # 4-7 users per department

    for ($i = 0; $i -lt $countForDept; $i++) {
        $first = $FirstNames | Get-Random
        $last  = $LastNames  | Get-Random
        $key   = "$first.$last"
        if ($usedNames.ContainsKey($key)) { continue }  # skip dupes, simplest approach
        $usedNames[$key] = $true

        $title = $titlesByDept[$dept] | Get-Random
        $extraGroups = $groupByDept[$dept]

        $sam = New-RandomUser -First $first -Last $last -Dept $dept -OUPath $deptOUPath `
            -Title $title -ExtraGroups $extraGroups

        $AllUsers += $sam
        Write-Host "  Created $first $last ($title, $dept) as $sam" -ForegroundColor Green
    }
}

# ---- CREATE A FEW REAL ADMIN-STYLE ACCOUNTS --------------------------------

Write-Host "`nCreating elevated/admin accounts..." -ForegroundColor Cyan

# A domain admin account separate from the built-in Administrator (realistic corp pattern)
New-ADUser -Name "IT Admin" -GivenName "IT" -Surname "Admin" `
    -SamAccountName "admin.it" -UserPrincipalName "admin.it@$((Get-ADDomain).DNSRoot)" `
    -Path "OU=IT,$CompanyOUPath" `
    -AccountPassword (ConvertTo-SecureString $DefaultPW -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "Domain Admins" -Members "admin.it" -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "IT-Admins" -Members "admin.it" -ErrorAction SilentlyContinue

# ---- SERVICE ACCOUNTS (for Kerberoasting practice) -------------------------

Write-Host "Creating service accounts (Kerberoasting targets)..." -ForegroundColor Cyan

$svcOUPath = "OU=ServiceAccounts,$CompanyOUPath"

$ServiceAccounts = @(
    @{ Sam = "svc-sql";   Spn = "MSSQLSvc/db01.$((Get-ADDomain).DNSRoot):1433" },
    @{ Sam = "svc-web";   Spn = "HTTP/web01.$((Get-ADDomain).DNSRoot)" },
    @{ Sam = "svc-backup"; Spn = "backupsvc/backup01.$((Get-ADDomain).DNSRoot)" }
)

foreach ($svc in $ServiceAccounts) {
    New-ADUser -Name $svc.Sam -SamAccountName $svc.Sam `
        -UserPrincipalName "$($svc.Sam)@$((Get-ADDomain).DNSRoot)" `
        -Path $svcOUPath `
        -AccountPassword (ConvertTo-SecureString $DefaultPW -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true -ErrorAction SilentlyContinue

    setspn -A $svc.Spn $svc.Sam | Out-Null
    # Make it juicier: put the SQL service account in Domain Admins, a real-world
    # misconfig that Kerberoasting + cracking this account would fully compromise.
    if ($svc.Sam -eq "svc-sql") {
        Add-ADGroupMember -Identity "Domain Admins" -Members $svc.Sam -ErrorAction SilentlyContinue
    }
    Write-Host "  Created $($svc.Sam) with SPN $($svc.Spn)" -ForegroundColor Green
}

# ---- ONE ACCOUNT VULNERABLE TO AS-REP ROASTING -----------------------------

Write-Host "Creating AS-REP roastable account..." -ForegroundColor Cyan

New-ADUser -Name "Legacy Service" -SamAccountName "legacy.svc" `
    -UserPrincipalName "legacy.svc@$((Get-ADDomain).DNSRoot)" `
    -Path $svcOUPath `
    -AccountPassword (ConvertTo-SecureString $DefaultPW -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true -ErrorAction SilentlyContinue

Set-ADAccountControl -Identity "legacy.svc" -DoesNotRequirePreAuth $true

Write-Host "`nDone. Summary:" -ForegroundColor Yellow
Write-Host "  Departments/OUs: $($Departments -join ', ')"
Write-Host "  Regular users created: $($AllUsers.Count)"
Write-Host "  Admin account: admin.it (Domain Admins)"
Write-Host "  Kerberoasting targets: svc-sql (Domain Admin!), svc-web, svc-backup"
Write-Host "  AS-REP roastable account: legacy.svc"
Write-Host "  Default password for ALL created accounts: $DefaultPW"
Write-Host "`nRemember: this is deliberately insecure. Don't reuse this structure anywhere real."
