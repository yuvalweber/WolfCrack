#Running a process with your current token
Function token-cmd
{
    $cmd = @"
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }

    [DllImport("advapi32", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)] 
    public struct SECURITY_ATTRIBUTES
    {
        public int    Length;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }

    public enum TOKEN_TYPE 
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    public enum SECURITY_IMPERSONATION_LEVEL 
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [DllImport("advapi32.dll", EntryPoint="DuplicateTokenEx",SetLastError=true)]
    public static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,TOKEN_TYPE TokenType, ref IntPtr DuplicateTokenHandle);
"@
    Add-Type -MemberDefinition $cmd -Namespace "token" -Name "cmd"

    [uint32]$GENERIC_ALL = 0x10000000
    $htoken = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token
    $DupToken = New-Object System.IntPtr
    $sa = New-Object token.cmd+SECURITY_ATTRIBUTES
    $sa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($sa)

    $si = New-Object token.cmd+STARTUPINFO
    $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
    $pi = New-Object token.cmd+ProcessInformation
    $CREATE_NEW_CONSOLE = 0x00000010
    $processPath = $env:comSpec

    [token.cmd]::DuplicateTokenEx($htoken,$GENERIC_ALL,[ref]$sa,[token.cmd+SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation,[token.cmd+TOKEN_TYPE]::TokenPrimary,[ref]$DupToken)|Out-Null
    [token.cmd]::CreateProcessWithTokenW($DupToken,0,$processPath,$null,$CREATE_NEW_CONSOLE,[System.IntPtr]::Zero,"c:\windows\system32",[ref]$si,[ref]$pi)|Out-Null
}






