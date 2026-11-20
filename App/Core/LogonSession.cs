// Copyright (c) Mouse Without Borders contributors. Licensed under the MIT license.
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;
using MouseWithoutBorders.Class;

namespace MouseWithoutBorders.Core;

// Follows PowerToys' SYSTEM winlogon-desktop launch, but exposes only existing
// authenticated input. No enrollment, file sharing, settings writes or user UI.
internal static class LogonSession
{
    internal const string Argument = "--mwb-logon";
    internal static bool Active { get; private set; }
    internal static string SettingsPath { get; private set; }

    private static string HandoffName(int session, string sid) => $@"Global\MWBP.Input.Handoff.{session}.{sid}";

    internal static EventWaitHandle CreateHandoff(int session, SecurityIdentifier user)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new EventWaitHandleSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(system);
        security.AddAccessRule(new EventWaitHandleAccessRule(system, EventWaitHandleRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new EventWaitHandleAccessRule(user,
            EventWaitHandleRights.Modify | EventWaitHandleRights.ReadPermissions, AccessControlType.Allow));
        try
        {
            var ready = EventWaitHandleAcl.Create(false, EventResetMode.ManualReset, HandoffName(session, user.Value), out bool created, security);
            if (created) return ready;
            ready.Dispose();
        }
        catch (Exception error) when (error is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            Logger.Log("Sign-in handoff signal unavailable: " + error.GetType().Name);
        }
        return null;
    }

    internal static bool WaitForHandoff(int session)
    {
        using var user = WindowsIdentity.GetCurrent();
        try
        {
            if (!EventWaitHandleAcl.TryOpenExisting(HandoffName(session, user.User.Value),
                EventWaitHandleRights.Modify | EventWaitHandleRights.ReadPermissions, out var ready)) return false;
            using (ready)
            {
                if (ready.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner
                    || !owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) return false;
                // A Windows automatic sign-in can start this app while Winlogon still receives input.
                if (WinAPI.IsMyDesktopActive()) ready.Set();
                return true; // The service releases this event after the former port owner exits.
            }
        }
        catch (Exception error) when (error is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        { return false; }
    }

    internal static string ResolveSettingsPath(string sid)
    {
        sid = PrivilegedInput.NormalizeAuthorizedUserSid(sid);
        using var service = Registry.LocalMachine.OpenSubKey(PrivilegedInput.ServiceRegistryPath + @"\Parameters");
        if (string.Equals(service?.GetValue(PrivilegedInput.AuthorizedUserSidValue) as string, sid, StringComparison.OrdinalIgnoreCase)
            && service.GetValue(PrivilegedInput.LocalAppDataValue) is string localAppData && IsLocalAppDataPath(localAppData))
            return Path.Combine(localAppData, "MouseWithoutBordersPlus", PortableApplication.SettingsFileName);
        using var profile = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
        string root = profile?.GetValue("ProfileImagePath") as string;
        if (string.IsNullOrWhiteSpace(root)) throw new IOException("The installed account profile is unavailable.");
        return Path.Combine(Environment.ExpandEnvironmentVariables(root), "AppData", "Local", "MouseWithoutBordersPlus", PortableApplication.SettingsFileName);
    }

    internal static bool IsLocalAppDataPath(string path) => !string.IsNullOrWhiteSpace(path)
        && Path.IsPathFullyQualified(path) && Path.GetPathRoot(path) is { Length: 3 } root
        && root[1] == ':' && new DriveInfo(root).DriveType is DriveType.Fixed;

    internal static bool Prepare(string[] args)
    {
        if (args.Length < 2 || args[1] != Argument) return false;
        using var identity = WindowsIdentity.GetCurrent();
        if (args.Length != 4 || !identity.IsSystem || !PrivilegedInput.IsProtectedCopy || !PrivilegedInput.ServiceModeAllowed
            || !PrivilegedInput.ApprovalScreensAllowed()
            || Process.GetCurrentProcess().SessionId != NativeMethods.WTSGetActiveConsoleSessionId()
            || !WinAPI.GetMyDesktop().Equals("winlogon", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Invalid logon input invocation.");
        SettingsPath = ResolveSettingsPath(args[3]);
        ValidatePreferences(PortableSettingsStore.Read(SettingsPath)); // Never create pairing or show recovery UI here.
        Active = true;
        Common.RunOnLogonDesktop = true;
        var stop = EventWaitHandle.OpenExisting(args[2]);
        _ = System.Threading.Tasks.Task.Run(() => { using (stop) stop.WaitOne(); Environment.Exit(0); });
        return true;
    }

    internal static void ValidatePreferences(Microsoft.PowerToys.Settings.UI.Library.MouseWithoutBordersSettings settings)
    {
        var properties = settings.Properties;
        if (string.IsNullOrWhiteSpace(properties.SecurityKey.Value) || properties.MachineID.Value <= 0
            || properties.MachineID.Value == (int)ID.ALL || properties.MachineMatrixString.Count(name => !string.IsNullOrWhiteSpace(name)) < 2)
            throw new InvalidDataException("Logon input requires an existing paired identity.");
    }

    // null means no process may run; a user token is deliberately unnecessary at boot.
    // The sign-in screen is one of the Windows approval screens: without that permission no
    // process runs there at all, so nothing listens on the network before a user signs in.
    internal static string SelectRole(string authorized, string interactiveUser, int session, bool approvalScreensAllowed) =>
        authorized == null || session < 0 || interactiveUser != null && interactiveUser != authorized ? null
            : interactiveUser != null ? PrivilegedInput.AgentArgument
            : approvalScreensAllowed ? Argument : null;

    internal static bool Allows(PackageType type) => type is PackageType.Keyboard or PackageType.Mouse
        or PackageType.Heartbeat or PackageType.Heartbeat_ex or PackageType.Heartbeat_ex_l2 or PackageType.Heartbeat_ex_l3
        or PackageType.Hello or PackageType.Hi or PackageType.Awake or PackageType.ByeBye or PackageType.HideMouse
        or PackageType.NextMachine;
}
