// Copyright (c) Mouse Without Borders contributors. Licensed under the MIT license.
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Xml.Linq;
using Microsoft.Win32;

namespace MouseWithoutBorders.Core;

internal static class LogonStartup
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupApprovedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string RunValue = "MouseWithoutBordersPlus";
    private const string TaskDescription = "VEIL MWBP starts in this Windows account at sign-in.";
    private static readonly XNamespace TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    internal static bool? IsEnabled()
    {
        using var scheduler = new Scheduler();
        var task = scheduler.Read();
        if (task != null && scheduler.Owns(task)) return IsTaskEnabled(task);
        var legacy = ReadLegacy(PrivilegedInput.ProtectedExecutable, PortableApplication.LegacyExecutable);
        return legacy == null ? false : legacy.Enabled;
    }

    internal static void ApplyInstallation(PortableInstallTransaction transaction, bool fresh, params string[] oldExecutables)
    {
        var legacy = ReadLegacy(oldExecutables);
        // An unknown value belongs to Windows; let the legacy entry keep its existing behavior.
        if (legacy == null ? !fresh : !legacy.Enabled.HasValue) return;
        using var scheduler = new Scheduler();
        var task = scheduler.Read();
        if (task == null) ChangeTask(transaction, scheduler, task, legacy?.Enabled ?? fresh);
        else if (!scheduler.Owns(task)) throw AnUnownedTaskExists();
        RemoveLegacy(transaction, legacy);
    }

    internal static void SetEnabled(bool enabled)
    {
        using var transaction = new PortableInstallTransaction();
        using var scheduler = new Scheduler();
        var task = scheduler.Read();
        if (task != null && !scheduler.Owns(task)) throw AnUnownedTaskExists();
        if (task == null ? enabled : IsTaskEnabled(task) != enabled) ChangeTask(transaction, scheduler, task, enabled);
        RemoveLegacy(transaction, ReadLegacy(PrivilegedInput.ProtectedExecutable, PortableApplication.LegacyExecutable));
        transaction.Complete();
    }

    internal static void RemoveInstallation(PortableInstallTransaction transaction, bool installed, params string[] executables)
    {
        if (installed)
        {
            using var scheduler = new Scheduler();
            var task = scheduler.Read();
            if (task != null && scheduler.Owns(task))
            {
                scheduler.Delete();
                transaction.OnRollback(() => RestoreTask(task, null));
            }
        }
        RemoveLegacy(transaction, ReadLegacy(executables));
    }

    private static InvalidOperationException AnUnownedTaskExists() =>
        new("A task with the MWBP sign-in task name is already registered by another installation.");

    private static void ChangeTask(PortableInstallTransaction transaction, Scheduler scheduler, XElement previous, bool enabled)
    {
        scheduler.Register(CreateTaskDefinition(scheduler.Sid, PrivilegedInput.ProtectedExecutable, enabled), update: previous != null);
        XElement current = null;
        bool readBack = false;
        transaction.OnRollback(() => RestoreTask(previous, current, readBack));
        current = scheduler.Read();
        readBack = true;
        if (current == null || !scheduler.Owns(current) || IsTaskEnabled(current) != enabled)
            throw new InvalidOperationException("Windows did not apply the MWBP sign-in task.");
    }

    private static void RestoreTask(XElement previous, XElement applied, bool readBack = true)
    {
        using var scheduler = new Scheduler();
        var current = scheduler.Read();
        if (readBack ? !XNode.DeepEquals(current, applied) : current == null || !scheduler.Owns(current)) return;
        if (previous != null) scheduler.Register(previous, update: current != null);
        else if (current != null) scheduler.Delete();
    }

    private sealed record LegacyEntry(string Command, RegistryValueKind Kind, bool? Enabled);

    private static LegacyEntry ReadLegacy(params string[] executables)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        string command = key?.GetValue(RunValue, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        if (!PortableApplication.StartupCommandTargets(command, executables)) return null;
        using var approval = Registry.CurrentUser.OpenSubKey(StartupApprovedKey);
        return new LegacyEntry(command, key.GetValueKind(RunValue), ReadLegacyApproval(approval?.GetValue(RunValue)));
    }

    internal static bool? ReadLegacyApproval(object value) => value switch
    {
        null => true,
        byte[] { Length: 12 } bytes when bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 => bytes[0] switch
        {
            2 => true,
            3 => false,
            _ => null,
        },
        _ => null,
    };

    private static void RemoveLegacy(PortableInstallTransaction transaction, LegacyEntry legacy)
    {
        if (legacy == null) return;
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
        if (!Equals(key?.GetValue(RunValue, null, RegistryValueOptions.DoNotExpandEnvironmentNames), legacy.Command)) return;
        key.DeleteValue(RunValue, throwOnMissingValue: false);
        transaction.OnRollback(() =>
        {
            using var restore = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
            if (restore.GetValue(RunValue) == null) restore.SetValue(RunValue, legacy.Command, legacy.Kind);
        });
    }

    internal static XElement CreateTaskDefinition(string sid, string executable, bool enabled)
    {
        XNamespace ns = TaskNamespace;
        return new XElement(ns + "Task", new XAttribute("version", "1.2"),
            new XElement(ns + "RegistrationInfo", new XElement(ns + "Description", TaskDescription)),
            new XElement(ns + "Triggers", new XElement(ns + "LogonTrigger", new XElement(ns + "UserId", sid))),
            new XElement(ns + "Principals", new XElement(ns + "Principal", new XAttribute("id", "User"),
                new XElement(ns + "UserId", sid), new XElement(ns + "LogonType", "InteractiveToken"),
                new XElement(ns + "RunLevel", "LeastPrivilege"))),
            new XElement(ns + "Settings", new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(ns + "DisallowStartIfOnBatteries", false), new XElement(ns + "StopIfGoingOnBatteries", false),
                new XElement(ns + "Enabled", enabled), new XElement(ns + "ExecutionTimeLimit", "PT0S")),
            new XElement(ns + "Actions", new XAttribute("Context", "User"),
                new XElement(ns + "Exec", new XElement(ns + "Command", executable),
                    new XElement(ns + "WorkingDirectory", System.IO.Path.GetDirectoryName(executable)))));
    }

    internal static bool OwnsDefinition(XElement task, string sid, string userName, string executable)
    {
        XNamespace ns = TaskNamespace;
        if ((string)task.Element(ns + "RegistrationInfo")?.Element(ns + "Description") != TaskDescription) return false;
        var principals = task.Element(ns + "Principals")?.Elements().ToArray();
        var triggers = task.Element(ns + "Triggers")?.Elements().ToArray();
        var actions = task.Element(ns + "Actions")?.Elements().ToArray();
        return principals is [{ } principal] && principal.Name == ns + "Principal"
            && IsCurrentUser((string)principal.Element(ns + "UserId"))
            && (string)principal.Element(ns + "LogonType") == "InteractiveToken"
            && (string)principal.Element(ns + "RunLevel") is null or "LeastPrivilege"
            && triggers is [{ } trigger] && trigger.Name == ns + "LogonTrigger"
            && IsCurrentUser((string)trigger.Element(ns + "UserId"))
            && actions is [{ } action] && action.Name == ns + "Exec"
            && string.Equals((string)action.Element(ns + "Command"), executable, StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrWhiteSpace((string)action.Element(ns + "Arguments"));

        bool IsCurrentUser(string value) => string.Equals(value, sid, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, userName, StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsTaskEnabled(XElement task) =>
        (bool?)task.Element(TaskNamespace + "Settings")?.Element(TaskNamespace + "Enabled") != false
        && (bool?)task.Element(TaskNamespace + "Triggers")?.Element(TaskNamespace + "LogonTrigger")?.Element(TaskNamespace + "Enabled") != false;

    private sealed class Scheduler : IDisposable
    {
        private const int TaskCreate = 2;
        private const int TaskUpdate = 4;
        private const int InteractiveToken = 3;
        private const int FileNotFound = unchecked((int)0x80070002);
        private readonly string userName;
        private readonly string taskName;
        private readonly dynamic folder;

        internal Scheduler()
        {
            using var identity = WindowsIdentity.GetCurrent();
            using var process = Process.GetCurrentProcess();
            Sid = identity.User?.Value;
            PortableApplication.ValidateInteractiveInstallerUser(Sid, process.SessionId);
            userName = identity.Name;
            taskName = "VEIL MWBP Sign-In " + Sid;
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true);
            dynamic service = Activator.CreateInstance(schedulerType);
            try
            {
                service.Connect();
                folder = service.GetFolder(@"\");
            }
            finally { Marshal.ReleaseComObject((object)service); }
        }

        internal string Sid { get; }

        internal XElement Read()
        {
            dynamic task;
            try { task = folder.GetTask(taskName); }
            catch (Exception error) when (error.HResult == FileNotFound) { return null; }
            try
            {
                var definition = XElement.Parse((string)task.Xml);
                definition.Element(TaskNamespace + "Settings")?.SetElementValue(TaskNamespace + "Enabled", (bool)task.Enabled);
                return definition;
            }
            finally { Marshal.ReleaseComObject((object)task); }
        }

        internal bool Owns(XElement task) => OwnsDefinition(task, Sid, userName, PrivilegedInput.ProtectedExecutable);

        internal void Register(XElement definition, bool update)
        {
            object task = folder.RegisterTask(taskName, definition.ToString(), update ? TaskUpdate : TaskCreate, Sid, null, InteractiveToken, null);
            Marshal.ReleaseComObject(task);
        }

        internal void Delete() => folder.DeleteTask(taskName, 0);

        public void Dispose() => Marshal.ReleaseComObject((object)folder);
    }
}
