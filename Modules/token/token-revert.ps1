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