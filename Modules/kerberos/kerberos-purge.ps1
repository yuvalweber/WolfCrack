#Purging kerberos tickets
Function kerberos-purge
{   
    $purge = @"
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
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING_IN
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_PURGE_TKT_CACHE_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID                       LogonId;
        public LSA_STRING_IN              ServerName;
        public LSA_STRING_IN              RealmName;
    }

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle,[In] ref LSA_STRING_IN PackageName,[Out] out UInt32 AuthenticationPackage);

    [DllImport("Secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle,uint AuthenticationPackage,IntPtr ProtocolSubmitBuffer,int SubmitBufferLength,out IntPtr ProtocolReturnBuffer,out ulong ReturnBufferLength,out int ProtocolStatus);

    [DllImport("secur32.dll", SetLastError = true)]
    public static extern int LsaRegisterLogonProcess(LSA_STRING_IN LogonProcessName,out IntPtr LsaHandle,out ulong SecurityMode);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);
"@   

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
       $LSAString = new-object kerberos.purge+LSA_STRING_IN
       $lsaHandle = New-Object System.IntPtr
       [System.UInt64]$SecurityMode = 0

       $LSAString.Length = [System.UInt16]$logonProcessName.Length
       $LSAString.MaximumLength = [System.UInt16]($logonProcessName.Length + 1)
       $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($logonProcessName)

       $ret = [kerberos.purge]::LsaRegisterLogonProcess($LSAString,[ref]$lsaHandle,[ref]$SecurityMode)

       return $lsaHandle
    }

    #Get lsa handle based on your privileges
    Function GetLsaHandle()
    {
        $lsahandle = New-Object System.IntPtr
        if(!(RunningAsAdmin))
        {
            Write-Host "`n[x] You Are Not Running As Admin" -ForegroundColor Red
            [int]$retcode = [kerberos.purge]::LsaConnectUntrusted([ref]$lsahandle)
        }

        else
        {
            #token-elevate impoersonate you to be System
            if(!([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM")){token-elevate|Out-Null}
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

    Function Purge($luid)
    {
        $protocolReturnBuffer = New-Object System.IntPtr
        $ReturnBufferLength = New-Object System.Int32
        $ProtocolStatus = New-Object System.Int32

        $request = New-Object kerberos.purge+KERB_PURGE_TKT_CACHE_REQUEST
        $request.MessageType = [kerberos.purge+KERB_PROTOCOL_MESSAGE_TYPE]::KerbPurgeTicketCacheMessage
        $request.LogonId = $luid
        $requestType = $request.GetType()

        $inputBufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inputBufferSize)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$inputBuffer,$false)

        $ntstats = [kerberos.purge]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$inputBuffer,$inputBufferSize,[ref]$protocolReturnBuffer,[ref]$ReturnBufferLength,[ref]$ProtocolStatus)

        if($inputBuffer -ne [System.IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
        }
    }

    #Main Function start HERE!!!
    $assemblies = [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
    Add-Type -MemberDefinition $purge -Namespace "kerberos" -Name "purge" -ReferencedAssemblies $assemblies.location -UsingNamespace System.Security.Principal

    $lsahandle = GetLsaHandle

    $retcode = New-Object System.Int32
    $authPackage = New-Object System.Int32
    $name = "kerberos"


    $LSAString = New-Object kerberos.purge+LSA_STRING_IN
    $LSAString.Length = [uint16]$name.Length
    $LSAString.MaximumLength = [uint16]($name.Length + 1)
    $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)
    $retcode = [kerberos.purge]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$LSAString,[ref]$authPackage)

    $strluid = GetCurrentLuid
    $intluid = [convert]::ToInt32($strluid,16)
    $luid = New-Object kerberos.purge+LUID
    $luid.LowPart = $intluid

    Purge $luid

    [kerberos.purge]::LsaDeregisterLogonProcess($lsaHandle)|Out-Null
    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){[token.elevate]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)|Out-Null}
}