// SmartScreenTest.cs
// Reproduces the winget validation security check (IAttachmentExecute)
// that blocks unsigned executables downloaded from the internet.
//
// Compile:  csc.exe /nologo /out:SmartScreenTest.exe SmartScreenTest.cs
// Run:      SmartScreenTest.exe <path-to-exe> [source-url]
//
// Exit codes:
//   0  - File passed security check
//   1  - File blocked by SmartScreen / policy check failed
//   2  - Usage error or exception

using System;
using System.IO;
using System.Runtime.InteropServices;

[ComImport, Guid("4125dd96-e03a-4103-8f70-e0597d803b9c")]
class AttachmentServices {}

[ComImport, Guid("73db1241-1e85-4581-8e4f-a81e1d0f8c57")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAttachmentExecute
{
    void SetClientTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
    void SetClientGuid(ref Guid guid);
    void SetLocalPath([MarshalAs(UnmanagedType.LPWStr)] string pszLocalPath);
    void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
    void SetSource([MarshalAs(UnmanagedType.LPWStr)] string pszSource);
    void SetReferrer([MarshalAs(UnmanagedType.LPWStr)] string pszReferrer);
    [PreserveSig] int CheckPolicy();
    [PreserveSig] int Prompt(IntPtr hwnd, uint action, out uint paction);
    [PreserveSig] int Save();
    [PreserveSig] int Execute(IntPtr hwnd, [MarshalAs(UnmanagedType.LPWStr)] string pszVerb, out IntPtr phProcess);
    [PreserveSig] int SaveWithUI(IntPtr hwnd);
    void ClearClientState();
}

class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: SmartScreenTest.exe <path-to-exe> [source-url]");
            Console.WriteLine();
            Console.WriteLine("Simulates the winget validation pipeline security check using");
            Console.WriteLine("the Windows IAttachmentExecute COM interface (SmartScreen).");
            return 2;
        }

        string filePath = Path.GetFullPath(args[0]);
        string source = args.Length > 1
            ? args[1]
            : "https://example.com/download";

        if (!File.Exists(filePath))
        {
            Console.WriteLine("ERROR: File not found: " + filePath);
            return 2;
        }

        Console.WriteLine("=== SmartScreen / IAttachmentExecute Security Check ===");
        Console.WriteLine("File:   " + filePath);
        Console.WriteLine("Source: " + source);
        Console.WriteLine();

        // Step 1: Authenticode signature check (managed)
        Console.WriteLine("[1] Authenticode Signature");
        try
        {
            var shell = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = string.Format(
                    "-NoProfile -Command \"(Get-AuthenticodeSignature -LiteralPath '{0}').Status\"",
                    filePath.Replace("'", "''")),
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var proc = System.Diagnostics.Process.Start(shell);
            string sigStatus = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit();
            Console.WriteLine("    Status: " + sigStatus);
            if (sigStatus != "Valid")
                Console.WriteLine("    >> FAIL - No valid digital signature");
            else
                Console.WriteLine("    >> PASS");
        }
        catch (Exception ex)
        {
            Console.WriteLine("    Could not check signature: " + ex.Message);
        }
        Console.WriteLine();

        // Step 2: Mark-of-the-Web check
        Console.WriteLine("[2] Mark-of-the-Web (MOTW)");
        try
        {
            var shell = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = string.Format(
                    "-NoProfile -Command \"Get-Content -LiteralPath '{0}' -Stream Zone.Identifier -ErrorAction SilentlyContinue\"",
                    filePath.Replace("'", "''")),
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var proc = System.Diagnostics.Process.Start(shell);
            string motw = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit();
            if (!string.IsNullOrEmpty(motw))
            {
                Console.WriteLine("    Present: YES");
                Console.WriteLine("    " + motw.Replace("\r\n", "  |  "));
            }
            else
            {
                Console.WriteLine("    Present: NO (no Zone.Identifier ADS)");
                Console.WriteLine("    Tip: Add MOTW to simulate internet download:");
                Console.WriteLine("      powershell -Command \"Set-Content -LiteralPath '<exe>' -Stream Zone.Identifier -Value '[ZoneTransfer]`r`nZoneId=3'\"");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("    Could not check MOTW: " + ex.Message);
        }
        Console.WriteLine();

        // Step 3: IAttachmentExecute COM check (what winget actually uses)
        Console.WriteLine("[3] IAttachmentExecute COM Security Check");
        Console.WriteLine("    (This is what winget validation calls internally)");
        int exitCode = 0;
        var ae = (IAttachmentExecute)new AttachmentServices();
        try
        {
            Guid clientGuid = Guid.NewGuid();
            ae.SetClientGuid(ref clientGuid);
            ae.SetLocalPath(filePath);
            ae.SetFileName(Path.GetFileName(filePath));
            ae.SetSource(source);

            Console.WriteLine();
            Console.WriteLine("    CheckPolicy()...");
            int policyHr = ae.CheckPolicy();
            Console.WriteLine("      Result: 0x{0:X8} ({1})", policyHr,
                policyHr == 0 ? "S_OK - policy passed" :
                policyHr == 1 ? "S_FALSE - policy flagged file" :
                "FAILED");

            Console.WriteLine("    Save()...");
            int saveHr = ae.Save();
            Console.WriteLine("      Result: 0x{0:X8}", saveHr);

            Console.WriteLine();
            if (saveHr == 0 && policyHr == 0)
            {
                Console.WriteLine("    >> PASSED - File allowed by SmartScreen");
            }
            else if (saveHr == 0 && policyHr == 1)
            {
                Console.WriteLine("    >> WARNING - Save() allowed locally, but CheckPolicy() flagged the file");
                Console.WriteLine("    >> On winget validation VMs (strict SmartScreen), this WILL be blocked");
                exitCode = 1;
            }
            else if (saveHr == unchecked((int)0x80004005))
            {
                Console.WriteLine("    >> BLOCKED (E_FAIL 0x80004005) - SmartScreen blocked the file");
                exitCode = 1;
            }
            else if (saveHr == unchecked((int)0x800704EC))
            {
                Console.WriteLine("    >> BLOCKED (ERROR_ACCESS_DISABLED_BY_POLICY 0x800704EC)");
                exitCode = 1;
            }
            else
            {
                Console.WriteLine("    >> FAILED with HRESULT 0x{0:X8}", saveHr);
                exitCode = 1;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("    Exception: " + ex.Message);
            Console.WriteLine("    HResult: 0x{0:X8}", ex.HResult);
            exitCode = 2;
        }
        finally
        {
            Marshal.ReleaseComObject(ae);
        }

        // Summary
        Console.WriteLine();
        Console.WriteLine("=== Summary ===");
        if (exitCode == 0)
        {
            Console.WriteLine("File passes SmartScreen checks.");
        }
        else
        {
            Console.WriteLine("File FAILS SmartScreen checks.");
            Console.WriteLine("Winget validation will report:");
            Console.WriteLine("  APPINSTALLER_CLI_ERROR_INSTALLER_SECURITY_CHECK_FAILED (0x8A15002D)");
            Console.WriteLine("  Installer failed security check. Result: 0x80004005 (E_FAIL)");
            Console.WriteLine();
            Console.WriteLine("Fix: Sign the exe with a trusted code-signing certificate.");
        }

        return exitCode;
    }
}
