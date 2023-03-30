# taskmgr_hook
Hook on task manager to make a process disappear.
Done by injecting a dll to the taskmgr process, which hooks the NtQuerySystemInformation to skip one of the processes, in my case notepad.exe.
