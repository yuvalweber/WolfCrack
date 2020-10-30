#This program loops over all the processes on the pc and return The Users,sids,token type and the id of different process she finds
Function token-list
{
    #Gets the user and the Sid of the Token specified
    Function Get-TokenUser($hToken,$SingleToken)
    {
        $TokenPtrSize = 0
        $success = [token.list]::GetTokenInformation($hToken,[token.list+TOKEN_INFORMATION_CLASS]::TokenUser,0,$TokenPtrSize,[ref]$TokenPtrSize)
        $TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
        $success = [token.list]::GetTokenInformation($hToken,[token.list+TOKEN_INFORMATION_CLASS]::TokenUser,$TokenPtr,$TokenPtrSize,[ref]$TokenPtrSize)

        $TokenObjectType = New-Object token.list+TOKEN_USER
        $TokenObjectType = $TokenObjectType.GetType()
        $token_user = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPtr,[type]$TokenObjectType)
        if($success)
        {
            $SidPtr = [intPtr]::Zero
            $result = [token.list]::ConvertSidToStringSid($token_user.User.Sid,[ref]$SidPtr)

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
        $success = [token.list]::GetTokenInformation($hToken,[token.list+TOKEN_INFORMATION_CLASS]::TokenType,0,$TokenPtrSize,[ref]$TokenPtrSize)
        $token_user = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
        $success = [token.list]::GetTokenInformation($hToken,[token.list+TOKEN_INFORMATION_CLASS]::TokenType,$token_user,$TokenPtrSize,[ref]$TokenPtrSize)

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

    $list = @"

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

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid ;
        public uint Attributes ;
    }

    public struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User ;
    }

    [DllImport("advapi32", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool ConvertSidToStringSid(IntPtr pSID,out IntPtr ptrSid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle,TOKEN_INFORMATION_CLASS TokenInformationClass,IntPtr TokenInformation,uint TokenInformationLength,out uint ReturnLength);
"@
    #Check if type already exist
    Add-Type -MemberDefinition $list -Namespace "token" -Name "list"|Out-Null
    
    $TOKEN_QUERY = 8
    $tokens = @()

    $processes = Get-Process
    #loops over every process and get the information needed about his token
    foreach($process in $processes)
    {
        try
        {
            $hProcess = $process.Handle
            $hToken = New-Object System.IntPtr
            $res = [token.list]::OpenProcessToken($hProcess,$TOKEN_QUERY,[ref]$hToken)

            $SingleToken = New-Object psobject
            Add-Member -InputObject $SingleToken -MemberType NoteProperty -Name "PID" -Value $process.Id

            Get-TokenUser $hToken $SingleToken|Out-Null
            Get-TokenType $hToken $SingleToken|Out-Null

            if(($tokens -notcontains $SingleToken) -and "" -ne $SingleToken ){$tokens += $SingleToken}
        }
        catch{}
    }

    #Get only the unique token ones
    $UniqueTokens = @($tokens[0])
    foreach($token in $tokens)
    {
        $res = $true
        foreach($unique in $UniqueTokens)
        {
            if($unique.User -eq $token.User){$res = $false}
        }
        if($res -and $token.User -ne $null){$UniqueTokens += $token}
    }  

    #print the process ids of the unqiue tokens,the sid and the username of the token owner, and the type
    foreach($unique in $UniqueTokens)
    {
        $username = $unique.User
        $sid =  $unique.Sid
        $type = $unique.Type
        $prid = $unique.PID

        $to_print = "`nUser: " + $username + "`nSid: " + $sid + "`nType: " + $type + "`nPid: " + $prid
        Write-Host $to_print
    }
}