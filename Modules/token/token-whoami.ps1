#Show information about your current token
Function token-whoami
{
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if($me.ImpersonationLevel -ne "None"){$to_print=  "`nUserName: " + $me.Name +"`nImpersonationLevel: " + $me.ImpersonationLevel + "`nSid: " + $me.User}
    else{$to_print=  "`nUserName: " + $me.Name +  "`nSid: " + $me.User}
    Write-Host $to_print
}