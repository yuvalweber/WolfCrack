#Get all the sessions on this pc
Function ts-sessions
{
    $tasks = tasklist /v /FO CSV
    #all the lines except the first one because it does not contain information about processes
    $tasks = $tasks[1..$tasks.Count]
    $sessions = @()
    $sessionIds = @()
    foreach($task in $tasks)
    {
        $splitted = $task.Split('"')
        $sessionName = $splitted[5]
        $sessionId = $splitted[7]
        $user = $splitted[13]
        $session = New-Object psobject
        try
        {
            if(($user -notmatch "N/A") -and ($user -notmatch "NT AUTHORITY") -and ($user -notmatch "Window Manager"))
            {
                Add-Member -InputObject $session -MemberType NoteProperty -Name "User" -Value $user
                Add-Member -InputObject $session -MemberType NoteProperty -Name "SessionName" -Value $sessionName
                Add-Member -InputObject $session -MemberType NoteProperty -Name "SessionId" -Value $sessionId
                if($session.SessionId -notin $sessionIds)
                {
                    $sessionIds += $session.SessionId 
                    $sessions += $session
                }
            }
        }
        catch{continue}
    }

    foreach($session in $sessions)
    {
        $to_print = "`nUser: " + $session.User + "`nSession Name: " + $session.SessionName + "`nSession Id: " + $session.SessionId 
        Write-Host $to_print
    }
}