// Packet Inspector - small launchers that sit next to the installer.
//
// Compiled twice from this one file (see scripts/publish-root.mjs):
//   Packet Inspector.exe            opens the installed app, or offers to install it
//   Uninstall Packet Inspector.exe  (/define:UNINSTALL) finds the installed copy and starts its uninstaller
//
// Both find the installation the same way Windows' "Apps" list does: through the
// uninstall entries in the registry, per-user (HKCU) first, then for everyone (HKLM).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

static class Program
{
    const string Product = "Packet Inspector";

    class Install
    {
        public string Version, Scope, UninstallCommand, Folder;
    }

    static List<Install> FindInstalls()
    {
        var found = new List<Install>();
        var places = new[] {
            new { Hive = RegistryHive.CurrentUser, View = RegistryView.Registry64, Scope = "just for you" },
            new { Hive = RegistryHive.LocalMachine, View = RegistryView.Registry64, Scope = "for everyone on this computer" },
            new { Hive = RegistryHive.LocalMachine, View = RegistryView.Registry32, Scope = "for everyone on this computer" },
        };
        foreach (var place in places)
        {
            try
            {
                using (var root = RegistryKey.OpenBaseKey(place.Hive, place.View))
                using (var un = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (un == null) continue;
                    foreach (var name in un.GetSubKeyNames())
                    {
                        using (var k = un.OpenSubKey(name))
                        {
                            var display = k == null ? null : k.GetValue("DisplayName") as string;
                            var cmd = k == null ? null : k.GetValue("UninstallString") as string;
                            if (display == null || cmd == null || !display.StartsWith(Product)) continue;
                            string exe, args;
                            Split(cmd, out exe, out args);
                            if (found.Exists(x => x.UninstallCommand == cmd)) continue;
                            found.Add(new Install { Version = k.GetValue("DisplayVersion") as string ?? "", Scope = place.Scope, UninstallCommand = cmd, Folder = Path.GetDirectoryName(exe) });
                        }
                    }
                }
            }
            catch { /* hive not readable: skip */ }
        }
        return found;
    }

    /** "C:\path with spaces\x.exe" /allusers  ->  exe + args */
    static void Split(string cmd, out string exe, out string args)
    {
        cmd = cmd.Trim();
        if (cmd.StartsWith("\""))
        {
            int end = cmd.IndexOf('"', 1);
            exe = end > 0 ? cmd.Substring(1, end - 1) : cmd.Trim('"');
            args = end > 0 ? cmd.Substring(end + 1).Trim() : "";
        }
        else
        {
            int sp = cmd.IndexOf(".exe ", StringComparison.OrdinalIgnoreCase);
            exe = sp > 0 ? cmd.Substring(0, sp + 4) : cmd;
            args = sp > 0 ? cmd.Substring(sp + 5).Trim() : "";
        }
    }

    static void Start(string exe, string args)
    {
        // ShellExecute, so Windows can show its permission prompt when needed.
        Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(exe) });
    }

    static string Here { get { return Path.GetDirectoryName(Application.ExecutablePath); } }

    [STAThread]
    static int Main()
    {
        Application.EnableVisualStyles();
        var installs = FindInstalls();
#if UNINSTALL
        if (installs.Count == 0)
        {
            MessageBox.Show(Product + " is not installed on this computer, so there is nothing to uninstall.", "Uninstall " + Product, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        var it = installs[0];
        var more = installs.Count > 1 ? "\r\n\r\nThere is also a second copy. Run this again afterwards to remove it too." : "";
        var answer = MessageBox.Show(Product + " " + it.Version + " is installed " + it.Scope + ".\r\n\r\nDo you want to uninstall it?" + more,
            "Uninstall " + Product, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
        if (answer != DialogResult.Yes) return 0;
        string exe, args;
        Split(it.UninstallCommand, out exe, out args);
        if (!File.Exists(exe))
        {
            MessageBox.Show("The uninstaller could not be found:\r\n" + exe + "\r\n\r\nRemove " + Product + " from Settings > Apps instead.", "Uninstall " + Product, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return 1;
        }
        try { Start(exe, args); }
        catch (System.ComponentModel.Win32Exception) { /* permission prompt declined */ }
        return 0;
#else
        foreach (var it in installs)
        {
            var app = Path.Combine(it.Folder ?? "", Product + ".exe");
            if (File.Exists(app)) { Start(app, ""); return 0; }
        }
        var installer = Path.Combine(Here, "Install " + Product + ".exe");
        if (!File.Exists(installer))
        {
            MessageBox.Show(Product + " is not installed on this computer yet, and the installer (\"Install " + Product + ".exe\") was not found next to this file.", Product, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 1;
        }
        var go = MessageBox.Show(Product + " is not installed on this computer yet.\r\n\r\nDo you want to install it now?", Product, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (go == DialogResult.Yes)
        {
            try { Start(installer, ""); } catch (System.ComponentModel.Win32Exception) { }
        }
        return 0;
#endif
    }
}
