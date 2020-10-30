#Add privileges to your current user
Function Privilege($mode)
{
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

    Add-Type -MemberDefinition $privilege -Namespace "Privilege" -Name "Enable"
    $res = [Privilege.Enable]::RtlAdjustPrivilege($target,$true,$false,[ref]$false)
    if($res){Write-Host "[x] Error, You Must Be Administrator For That, or you can't assign this privilege to yourself" -ForegroundColor Red}
    else{Write-Host "Privilege '$target' OK"}
}