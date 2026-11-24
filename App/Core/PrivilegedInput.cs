// Copyright (c) Mouse Without Borders contributors. Licensed under the MIT license.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using MouseWithoutBorders.Class;
using PowerToys.GPOWrapper;

namespace MouseWithoutBorders.Core;

// Injection stays in a narrow SYSTEM worker. Boot uses a separate input-only winlogon role.
internal static class PrivilegedInput
{
    internal const string ServiceName = "MouseWithoutBordersPlus.Input";
    internal const string ServiceArgument = "--mwb-input-service";
    internal const string AgentArgument = "--mwb-input-agent";
    internal const string InstallArgument = "--mwb-input-install";
    internal const string RemoveArgument = "--mwb-input-remove";
    internal const string UninstallArgument = "--mwb-input-uninstall";
    internal const string ServiceRegistryPath = @"SYSTEM\CurrentControlSet\Services\" + ServiceName;
    internal const string AuthorizedUserSidValue = "AuthorizedUserSid";
    internal const string LocalAppDataValue = "OwnerLocalAppData";
    internal const string ApprovalScreensArgument = "--mwb-input-approval-screens";
    internal const string ApprovalScreensValue = "BlockApprovalScreens";
    private const uint DesktopJournalPlayback = 0x0020;

    // Windows approval (UAC), sign-in and lock screens run on a separate desktop. Installing the
    // service allows input there, as it always has; an administrator can block those screens
    // while administrator apps stay controllable. No value, or 0, means allowed. Anything else,
    // or a value that cannot be read, means blocked. The value lives beside the service
    // configuration, which only administrators can write, and is enforced by the SYSTEM worker:
    // the ordinary app that asks for input cannot change it.
    internal static bool ReadApprovalScreens(Func<object> readValue)
    {
        try { object value = readValue(); return value == null || value is int number && number == 0; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { return false; }
    }

    internal static bool ApprovalScreensAllowed() => ReadApprovalScreens(() =>
    {
        using var parameters = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ServiceRegistryPath + @"\Parameters");
        return parameters?.GetValue(ApprovalScreensValue);
    });

    /// <summary>True when input must not be applied to the desktop with this name.</summary>
    internal static bool DesktopBlocked(ReadOnlySpan<char> desktopName, bool approvalScreensAllowed) =>
        !approvalScreensAllowed && !desktopName.Equals("Default", StringComparison.OrdinalIgnoreCase);

    // Read once when the worker starts; changing the setting restarts the service and its worker.
    private static bool agentAllowsApprovalScreens;
    [ThreadStatic] private static char[] desktopNameBuffer;

    private static bool IsBlockedDesktop(IntPtr desktop)
    {
        if (agentAllowsApprovalScreens) return false; // No extra call on the allowed path.
        char[] name = desktopNameBuffer ??= new char[64];
        // A name that cannot be read, or does not fit, is not the ordinary desktop.
        if (!GetUserObjectInformation(desktop, NativeMethods.UOI_NAME, name, name.Length * sizeof(char), out int bytes) || bytes < sizeof(char))
            return true;
        return DesktopBlocked(name.AsSpan(0, Math.Min(name.Length, (bytes / sizeof(char)) - 1)), false);
    }

    // Letting go of a key or button cannot press anything. The worker still applies such a
    // release on a blocked desktop when it pressed that key itself: Win+L or Enter are pressed
    // on the ordinary desktop and released after the lock or approval screen has appeared, and
    // a release that never arrives would leave the key held for whoever uses the PC next.
    internal static bool IsPureRelease(NativeMethods.INPUT64 input) => input.type == 1
        ? (input.ki.dwFlags & (int)NativeMethods.KEYEVENTF.KEYUP) != 0
        : input.type == 0 && input.mi.dwFlags != 0 && (input.mi.dwFlags & ~(4 | 16 | 64 | 256)) == 0;

    internal static string NormalizeAuthorizedUserSid(string value) => new SecurityIdentifier(value).Value;

    internal static string ReadAuthorizedUserSid(Func<object> readValue)
    {
        try { return readValue() is string value ? NormalizeAuthorizedUserSid(value) : null; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException)
        { return null; }
    }

    private static string AuthorizedUserSid() => ReadAuthorizedUserSid(() =>
    {
        using var parameters = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(ServiceRegistryPath + @"\Parameters");
        return parameters?.GetValue(AuthorizedUserSidValue);
    });
    internal static string ProtectedDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "MouseWithoutBordersPlus");
    internal static string ProtectedExecutable => Path.Combine(ProtectedDirectory, "MouseWithoutBordersPlus.exe");
    private static string Executable => Environment.ProcessPath ?? throw new IOException("The application executable is unavailable.");
    // Reply v2 adds failure metadata; never interpret a v1 worker's held-input reply as v2.
    private static string PipeName(int session) => "MouseWithoutBordersPlus/Input/v2/" + session;
    internal static string CapturePipeName(int session) => "MouseWithoutBordersPlus/Capture/v1/" + session;
    internal const int CaptureFrameSize = 32;
    internal const byte CaptureMouseKind = 0;
    internal const byte CaptureKeyboardKind = 1;
    internal const byte CaptureGhostReleaseKind = 2;
    internal const byte CaptureSyncDownKind = 3;
    internal const int ReplySize = 12;
    internal enum InjectionStage : uint { None, OpenDesktop, AttachDesktop, SendInput, RestoreDesktop, ApprovalScreenBlocked }
    internal readonly record struct InjectionFailure(InjectionStage Stage, int Error);
    internal readonly record struct CaptureFrame(byte Kind, int WParam, int First, int Second, int Third, int Fourth, long ExtraInfo);

    [StructLayout(LayoutKind.Sequential)]
    private struct CaptureMouseHookStruct
    {
        internal int PtX;
        internal int PtY;
        internal int MouseData;
        internal int Flags;
        internal int Time;
        internal IntPtr DwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CaptureKeyboardHookStruct
    {
        internal int VkCode;
        internal int ScanCode;
        internal int Flags;
        internal int Time;
        internal IntPtr DwExtraInfo;
    }
    internal static bool IsProtectedCopy => Path.GetFullPath(Executable).Equals(ProtectedExecutable, StringComparison.OrdinalIgnoreCase);
    private static NamedPipeClientStream inputPipe;
    private static SafeProcessHandle inputAgent;
    private static bool brokerOwnsInput;
    // A pipe reply can be lost after a DOWN was applied. Keep its release debt
    // independently of the worker process so replacing that worker cannot lose it.
    private static readonly Dictionary<long, NativeMethods.INPUT64> clientHeldInput = new();
    private static bool recoveringInput;
    private static readonly HashSet<string> reportedFailures = new();
    private static InjectionFailure lastRestoreFailure;
    private static bool clientNeedsDrain;
    internal static bool HasHeldInput
    {
        get
        {
            if (brokerOwnsInput) DiscardExitedAgent();
            return brokerOwnsInput;
        }
    }

    private static void DiscardExitedAgent()
    {
        // An exited owner cannot deliver a late cleanup; its cached pipe is stale even when no key is held.
        if (inputAgent == null || NativeMethods.WaitForSingleObject(inputAgent.DangerousGetHandle(), 0) != 0) return;
        inputPipe?.Dispose(); inputPipe = null;
        inputAgent.Dispose(); inputAgent = null;
        brokerOwnsInput = clientHeldInput.Count != 0;
        clientNeedsDrain |= clientHeldInput.Count != 0;
    }

    // Called under InputSimulationLock. Disconnect makes the agent release its own
    // keys even when this desktop cannot observe them through GetAsyncKeyState.
    internal static void ReleaseConnection()
    {
        inputPipe?.Dispose(); inputPipe = null;
        clientNeedsDrain |= clientHeldInput.Count != 0;
        // Keep uncertain ownership until that agent drains it or exits.
    }

    private static readonly (int Down, int Up, int Data)[] MouseButtons = [(2, 4, 0), (8, 16, 0), (32, 64, 0), (128, 256, 1), (128, 256, 2)];

    internal static bool ServiceModeAllowed => GPOWrapper.GetConfiguredMwbAllowServiceModeValue() != GpoRuleConfigured.Disabled;

    internal static bool PolicyAllowsRole(string role, GpoRuleConfigured appPolicy, GpoRuleConfigured servicePolicy) =>
        role is RemoveArgument or UninstallArgument || appPolicy != GpoRuleConfigured.Disabled
            && (role == InstallArgument || servicePolicy != GpoRuleConfigured.Disabled);

    internal static bool TryRun(string[] args)
    {
        if (args.Length < 2 || args[1] is not (ServiceArgument or AgentArgument or InstallArgument or RemoveArgument or UninstallArgument or ApprovalScreensArgument)) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!PolicyAllowsRole(args[1], GPOWrapper.GetConfiguredMouseWithoutBordersEnabledValue(), GPOWrapper.GetConfiguredMwbAllowServiceModeValue()))
                throw new UnauthorizedAccessException("Protected input is disabled by administrator policy.");
            if (args[1] == ApprovalScreensArgument)
            {
                if (args.Length != 3 || args[2] is not ("on" or "off") || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new UnauthorizedAccessException("Administrator approval is required to change approval screen control.");
                PortableInstallLifecycle.ConfigureApprovalScreens(args[2] == "on");
            }
            else if (args[1] is InstallArgument or RemoveArgument or UninstallArgument)
            {
                bool remove = args[1] != InstallArgument;
                if ((remove ? args.Length != 2 : args.Length is not (3 or 4))
                    || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new UnauthorizedAccessException("Administrator approval is required to manage protected input.");
                PortableInstallLifecycle.ConfigurePrivilegedInput(remove, remove ? null : args[2], args[1] == UninstallArgument,
                    args.Length == 4 ? args[3] : null);
            }
            else
            {
                if (!identity.IsSystem || !IsProtectedCopy) throw new UnauthorizedAccessException("The input role requires the protected SYSTEM installation.");
                if (args[1] == ServiceArgument)
                {
                    if (args.Length != 2 || Process.GetCurrentProcess().SessionId != 0) throw new ArgumentException("Invalid service invocation.");
                    ServiceBase.Run(new InputService());
                }
                else
                {
                    if (args.Length != 4 || Process.GetCurrentProcess().SessionId == 0) throw new ArgumentException("Invalid input-agent invocation.");
                    // The STA entry thread can own COM windows, which prevent desktop changes.
                    System.Threading.Tasks.Task.Run(() => RunAgent(args[2], new SecurityIdentifier(args[3]))).GetAwaiter().GetResult();
                }
            }
        }
        catch (Exception error)
        {
            // A service/agent failure must never open a privileged first-launch/settings UI.
            Console.Error.WriteLine(error.Message);
            Environment.ExitCode = 1;
        }
        return true;
    }

    // Called inside InputSimulationLock for protected foregrounds, held ownership or native rejection.
    internal static bool TrySend(NativeMethods.INPUT64 input, out uint sent)
    {
        sent = 0;
        if (!IsProtectedCopy) return false;
        DiscardExitedAgent();
        string phase = "policy";
        try
        {
            // A revoked policy blocks new ownership, while already-owned input can still drain.
            if (!brokerOwnsInput && Setting.Values.AllowServiceModeIsGpoConfigured) return false;
            if (inputPipe == null)
            {
                phase = "connect";
                inputPipe = new NamedPipeClientStream(".", PipeName(Process.GetCurrentProcess().SessionId), PipeDirection.InOut, PipeOptions.Asynchronous);
                inputPipe.Connect(0);
                phase = "owner verification";
                var owner = inputPipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
                if (!Equals(owner, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)))
                    throw new UnauthorizedAccessException("The input endpoint is not owned by SYSTEM.");
                phase = "process verification";
                if (!GetNamedPipeServerProcessId(inputPipe.SafePipeHandle, out uint server)) throw new Win32Exception();
                var verified = VerifyExecutable((int)server, Process.GetCurrentProcess().SessionId);
                inputAgent?.Dispose(); inputAgent = verified;
                clientNeedsDrain |= clientHeldInput.Count != 0;
            }
            phase = "owned release drain";
            if (!DrainReconnectedInput()) return true;
            if (!brokerOwnsInput && Setting.Values.AllowServiceModeIsGpoConfigured) return false;
            phase = "input exchange";
            sent = ExchangeInput(input);
            if (sent != 0 && recoveringInput)
            {
                recoveringInput = false;
                reportedFailures.Clear();
                Logger.Log("Protected input recovered: worker reply received after owned releases.");
            }
            return true;
        }
        catch (Exception error) when (error is IOException or System.TimeoutException or UnauthorizedAccessException or Win32Exception or OperationCanceledException)
        {
            inputPipe?.Dispose(); inputPipe = null;
            clientNeedsDrain |= clientHeldInput.Count != 0;
            if (reportedFailures.Add($"{phase}:{error.HResult}"))
                Logger.Log($"Protected input interrupted: phase={phase}; {error.GetType().Name}; HRESULT=0x{error.HResult:X8}; Win32={(error is Win32Exception native ? native.NativeErrorCode : 0)}; pending owned releases={clientHeldInput.Count}.");
            recoveringInput = true;
            return false;
        }
    }

    private static uint ExchangeInput(NativeMethods.INPUT64 input) => ExchangeInputFrame(input, false);

    private static bool DrainClientHeldInput()
    {
        foreach (var release in new List<NativeMethods.INPUT64>(clientHeldInput.Values))
            if (ExchangeInputFrame(release, true) == 0) return false;
        return true;
    }

    private static bool DrainReconnectedInput()
    {
        if (!clientNeedsDrain) return true;
        if (!DrainClientHeldInput()) return false;
        clientNeedsDrain = false;
        return true;
    }

    private static uint ExchangeInputFrame(NativeMethods.INPUT64 input, bool draining)
    {
        // Match the existing input TCP send deadline; a stalled agent must release the input lock.
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        byte[] data = new byte[Marshal.SizeOf<NativeMethods.INPUT64>()];
        MemoryMarshal.Write(data.AsSpan(), in input);
        bool down = input.type == 1 ? (input.ki.dwFlags & (int)NativeMethods.KEYEVENTF.KEYUP) == 0
            : (input.mi.dwFlags & (2 | 8 | 32 | 128)) != 0;
        var beforeDown = down ? new Dictionary<long, NativeMethods.INPUT64>(clientHeldInput) : null;
        if (down) TrackHeldInput(clientHeldInput, input);
        // A failed MOVE/UP with no previous DOWN cannot manufacture a held key.
        brokerOwnsInput |= clientHeldInput.Count != 0;
        inputPipe.WriteAsync(data, 0, data.Length, deadline.Token).GetAwaiter().GetResult();
        byte[] reply = new byte[ReplySize];
        inputPipe.ReadExactlyAsync(reply, deadline.Token).AsTask().GetAwaiter().GetResult();
        uint status = BinaryPrimitives.ReadUInt32LittleEndian(reply);
        var failure = ReadFailure(reply);
        uint count = status & 1;
        if (count != 0) TrackHeldInput(clientHeldInput, input);
        else if (beforeDown != null)
        {
            clientHeldInput.Clear();
            foreach (var entry in beforeDown) clientHeldInput.Add(entry.Key, entry.Value);
        }
        if (!draining && (status >> 1) == 0) clientHeldInput.Clear();
        brokerOwnsInput = (status >> 1) != 0 || clientHeldInput.Count != 0;
        if (count == 0)
        {
            if (reportedFailures.Add($"inject:{failure.Stage}:{failure.Error}"))
                Logger.Log($"Protected input rejected: stage={failure.Stage}; Win32={failure.Error}; pending owned releases={clientHeldInput.Count}.");
            recoveringInput = true;
        }
        else if (failure.Stage == InjectionStage.RestoreDesktop)
        {
            if (failure != lastRestoreFailure)
                Logger.Log($"Protected input desktop restore failed: Win32={failure.Error}; input was applied.");
            lastRestoreFailure = failure;
        }
        else lastRestoreFailure = default;
        return count;
    }

    internal static InjectionFailure ReadFailure(ReadOnlySpan<byte> reply) => new(
        (InjectionStage)BinaryPrimitives.ReadUInt32LittleEndian(reply.Slice(4)),
        BinaryPrimitives.ReadInt32LittleEndian(reply.Slice(8)));

    internal static void WriteReply(Span<byte> reply, uint count, int held, InjectionFailure failure)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(reply, count | ((uint)held << 1));
        BinaryPrimitives.WriteUInt32LittleEndian(reply.Slice(4), (uint)failure.Stage);
        BinaryPrimitives.WriteInt32LittleEndian(reply.Slice(8), failure.Error);
    }

    private static SafeProcessHandle VerifyExecutable(int processId, int session)
    {
        var process = new SafeProcessHandle(NativeMethods.OpenProcess(0x101000, false, (uint)processId), true);
        if (process.IsInvalid) { process.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        try
        {
            char[] path = new char[32768];
            uint length = (uint)path.Length;
            if (!ProcessIdToSessionId((uint)processId, out uint actualSession)
                || !NativeMethods.QueryFullProcessImageName(process.DangerousGetHandle(), 0, path, ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (actualSession != session || !new string(path, 0, (int)length).Equals(ProtectedExecutable, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("The input endpoint belongs to a different application or Windows session.");
            return process;
        }
        catch { process.Dispose(); throw; }
    }

    private static SecurityIdentifier InteractiveUser(int session)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (NativeMethods.WTSQueryUserToken((uint)session, ref token) == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            using var user = new WindowsIdentity(token);
            return user.User ?? throw new UnauthorizedAccessException("No interactive Windows user is available.");
        }
        finally { if (token != IntPtr.Zero) NativeMethods.CloseHandle(token); }
    }

    private static NamedPipeServerStream CreateUserSessionPipe(string pipeName, SecurityIdentifier user)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(system);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.ReadWrite, AccessControlType.Deny));
        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous, 0, 0, security);
    }

    private static NamedPipeServerStream CreateAgentPipe(SecurityIdentifier user, int session) =>
        CreateUserSessionPipe(PipeName(session), user);

    private static NamedPipeServerStream CreateCapturePipe(SecurityIdentifier user, int session) =>
        CreateUserSessionPipe(CapturePipeName(session), user);

    internal static void WriteCaptureFrame(Span<byte> buffer, CaptureFrame frame)
    {
        buffer[0] = frame.Kind;
        buffer[1] = 0;
        buffer[2] = 0;
        buffer[3] = 0;
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4, 4), frame.WParam);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(8, 4), frame.First);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(12, 4), frame.Second);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(16, 4), frame.Third);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(20, 4), frame.Fourth);
        BinaryPrimitives.WriteInt64LittleEndian(buffer.Slice(24, 8), frame.ExtraInfo);
    }

    internal static CaptureFrame ReadCaptureFrame(ReadOnlySpan<byte> buffer) => new(
        buffer[0],
        BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(4, 4)),
        BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(8, 4)),
        BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(12, 4)),
        BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(16, 4)),
        BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(20, 4)),
        BinaryPrimitives.ReadInt64LittleEndian(buffer.Slice(24, 8)));

    internal static bool TryExchangeCaptureFrame(Stream pipe, CaptureFrame frame, int timeoutMilliseconds, out bool suppress) =>
        TryExchangeCaptureFrame(pipe, frame, timeoutMilliseconds, new byte[CaptureFrameSize], new byte[1], out suppress);

    internal static bool TryExchangeCaptureFrame(Stream pipe, CaptureFrame frame, int timeoutMilliseconds, byte[] frameBuffer, byte[] replyBuffer, out bool suppress)
    {
        suppress = false;
        try
        {
            WriteCaptureFrame(frameBuffer, frame);
            using var deadline = new CancellationTokenSource(timeoutMilliseconds);
            pipe.WriteAsync(frameBuffer, 0, CaptureFrameSize, deadline.Token).GetAwaiter().GetResult();
            pipe.ReadExactlyAsync(replyBuffer.AsMemory(0, 1), deadline.Token).AsTask().GetAwaiter().GetResult();
            suppress = replyBuffer[0] != 0;
            return true;
        }
        catch (Exception error) when (error is IOException or ObjectDisposedException or OperationCanceledException or EndOfStreamException)
        {
            return false;
        }
    }

    internal static NamedPipeClientStream TryConnectCapture(int timeoutMilliseconds = 10)
    {
        if (!IsProtectedCopy || Setting.Values.AllowServiceModeIsGpoConfigured) return null;
        int session = Process.GetCurrentProcess().SessionId;
        NamedPipeClientStream pipe = null;
        try
        {
            pipe = new NamedPipeClientStream(".", CapturePipeName(session), PipeDirection.InOut, PipeOptions.Asynchronous);
            pipe.Connect(timeoutMilliseconds);
            var owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
            if (!Equals(owner, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)))
                throw new UnauthorizedAccessException("The capture endpoint is not owned by SYSTEM.");
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint server)) throw new Win32Exception();
            using var verified = VerifyExecutable((int)server, session);
            var connected = pipe;
            pipe = null;
            return connected;
        }
        catch (Exception error) when (error is IOException or System.TimeoutException or UnauthorizedAccessException or Win32Exception or OperationCanceledException)
        {
            return null;
        }
        finally
        {
            pipe?.Dispose();
        }
    }

    internal static bool ShouldSeedPhysicalKey(int vk) =>
        vk is >= 8 and <= 254 and not (0x10 or 0x11 or 0x12 or 0xE7 or >= 0xF0);

    private static bool IsDefaultInputDesktop()
    {
        IntPtr desktop = NativeMethods.OpenInputDesktop(0, false, NativeMethods.DESKTOP_READOBJECTS);
        if (desktop == IntPtr.Zero) return false;
        try { return !IsBlockedDesktop(desktop); }
        finally { CloseDesktop(desktop); }
    }

    private static void RunCaptureServer(EventWaitHandle stop, SecurityIdentifier user, int session)
    {
        NamedPipeServerStream server = null;
        uint activeHookThreadId = 0;
        var registered = ThreadPool.RegisterWaitForSingleObject(stop, (_, _) =>
        {
            Volatile.Read(ref server)?.Dispose();
            uint tid = Volatile.Read(ref activeHookThreadId);
            if (tid != 0) _ = NativeMethods.PostThreadMessage(tid, 0x0012, IntPtr.Zero, IntPtr.Zero);
        }, null, Timeout.Infinite, true);
        try
        {
            while (!stop.WaitOne(0))
            {
                bool backOff = false;
                using var hooksReady = new ManualResetEventSlim(false);
                using (var connection = CreateCapturePipe(user, session))
                {
                Volatile.Write(ref server, connection);
                if (stop.WaitOne(0)) { Volatile.Write(ref server, null); break; }
                System.Threading.Thread hookThread = null;
                uint hookThreadId = 0;
                int captureActive = 0;
                try
                {
                    connection.WaitForConnection();
                    Volatile.Write(ref server, null);
                    if (stop.WaitOne(0)) break;
                    if (!GetNamedPipeClientProcessId(connection.SafePipeHandle, out uint client)) throw new Win32Exception();
                    using var verified = VerifyExecutable((int)client, session);
                    byte[] frameBuffer = new byte[CaptureFrameSize];
                    byte[] replyBuffer = new byte[1];
                    Volatile.Write(ref captureActive, 1);
                    bool hooksInstalled = false;
                    hookThread = new System.Threading.Thread(() =>
                    {
                        int mouseHook = 0, keyboardHook = 0;
                        NativeMethods.HookProc mouseProc = null, keyboardProc = null;
                        bool readySignaled = false;
                        var trackedKeys = new HashSet<int>();
                        int[] scratchKeys = new int[32];
                        bool FlushGhostKeys(int activeVk = -1)
                        {
                            if (trackedKeys.Count == 0) return true;
                            int count = 0;
                            foreach (int vk in trackedKeys)
                            {
                                if (vk == activeVk || (NativeMethods.GetAsyncKeyState((IntPtr)vk) & 0x8000) != 0) continue;
                                if (count == scratchKeys.Length) Array.Resize(ref scratchKeys, scratchKeys.Length * 2);
                                scratchKeys[count++] = vk;
                            }
                            for (int i = 0; i < count; i++)
                            {
                                int vk = scratchKeys[i];
                                trackedKeys.Remove(vk);
                                if (Volatile.Read(ref captureActive) == 0
                                    || !TryExchangeCaptureFrame(connection, new CaptureFrame(CaptureGhostReleaseKind, 0, vk, 0, 0, 0, 0),
                                        140, frameBuffer, replyBuffer, out _))
                                    return false;
                            }
                            return true;
                        }
                        try
                        {
                            _ = NativeMethods.PeekMessage(out _, IntPtr.Zero, 0, 0, 0);
                            uint threadId = NativeMethods.GetCurrentThreadId();
                            hookThreadId = threadId;
                            IntPtr module =
#if PORTABLE_SINGLE_FILE
                                NativeMethods.GetModuleHandle(null);
#else
                                Marshal.GetHINSTANCE(typeof(PrivilegedInput).Assembly.GetModules()[0]);
#endif
                            mouseProc = (nCode, wParam, lParam) =>
                            {
                                if (nCode < 0 || Volatile.Read(ref captureActive) == 0)
                                    return NativeMethods.CallNextHookEx(mouseHook, nCode, wParam, lParam);
                                if (!agentAllowsApprovalScreens && !IsDefaultInputDesktop())
                                    return NativeMethods.CallNextHookEx(mouseHook, nCode, wParam, lParam);
                                CaptureMouseHookStruct data;
                                unsafe { data = *(CaptureMouseHookStruct*)lParam; }
                                var frame = new CaptureFrame(CaptureMouseKind, wParam, data.PtX, data.PtY, data.MouseData, data.Flags, (long)data.DwExtraInfo);
                                if (((data.Flags & 1) == 0 && !FlushGhostKeys())
                                    || !TryExchangeCaptureFrame(connection, frame, 140, frameBuffer, replyBuffer, out bool suppress))
                                {
                                    Volatile.Write(ref captureActive, 0);
                                    _ = NativeMethods.PostThreadMessage(threadId, 0x0012, IntPtr.Zero, IntPtr.Zero);
                                    return NativeMethods.CallNextHookEx(mouseHook, nCode, wParam, lParam);
                                }
                                return suppress ? 1 : NativeMethods.CallNextHookEx(mouseHook, nCode, wParam, lParam);
                            };
                            keyboardProc = (nCode, wParam, lParam) =>
                            {
                                if (nCode < 0 || Volatile.Read(ref captureActive) == 0)
                                    return NativeMethods.CallNextHookEx(keyboardHook, nCode, wParam, lParam);
                                if (!agentAllowsApprovalScreens && !IsDefaultInputDesktop())
                                    return NativeMethods.CallNextHookEx(keyboardHook, nCode, wParam, lParam);
                                CaptureKeyboardHookStruct data;
                                unsafe { data = *(CaptureKeyboardHookStruct*)lParam; }
                                bool physical = (data.Flags & 0x10) == 0 && data.VkCode is >= 1 and <= 254;
                                bool up = (data.Flags & (int)WM.LLKHF.UP) != 0;
                                if (physical && !FlushGhostKeys(activeVk: data.VkCode))
                                {
                                    Volatile.Write(ref captureActive, 0);
                                    _ = NativeMethods.PostThreadMessage(threadId, 0x0012, IntPtr.Zero, IntPtr.Zero);
                                    return NativeMethods.CallNextHookEx(keyboardHook, nCode, wParam, lParam);
                                }
                                var frame = new CaptureFrame(CaptureKeyboardKind, wParam, data.VkCode, data.ScanCode, data.Flags, data.Time, (long)data.DwExtraInfo);
                                if (!TryExchangeCaptureFrame(connection, frame, 140, frameBuffer, replyBuffer, out bool suppress))
                                {
                                    Volatile.Write(ref captureActive, 0);
                                    _ = NativeMethods.PostThreadMessage(threadId, 0x0012, IntPtr.Zero, IntPtr.Zero);
                                    return NativeMethods.CallNextHookEx(keyboardHook, nCode, wParam, lParam);
                                }
                                // Only track unsuppressed local key-downs via GetAsyncKeyState; Windows does not update
                                // async key state for suppressed remote keys, so querying them would falsely prune holds.
                                if (physical)
                                {
                                    if (!up && !suppress) trackedKeys.Add(data.VkCode);
                                    else trackedKeys.Remove(data.VkCode);
                                }
                                return suppress ? 1 : NativeMethods.CallNextHookEx(keyboardHook, nCode, wParam, lParam);
                            };
                            mouseHook = NativeMethods.SetWindowsHookEx(WM.WH_MOUSE_LL, mouseProc, module, 0);
                            keyboardHook = NativeMethods.SetWindowsHookEx(WM.WH_KEYBOARD_LL, keyboardProc, module, 0);
                            if (mouseHook == 0 || keyboardHook == 0)
                            {
                                Logger.Log($"Privileged capture hook install failed: mouse={mouseHook}, keyboard={keyboardHook}, err={Marshal.GetLastWin32Error()}.");
                                return;
                            }
                            if (agentAllowsApprovalScreens || IsDefaultInputDesktop())
                            {
                                for (int vk = 8; vk <= 254; vk++)
                                {
                                    if (!ShouldSeedPhysicalKey(vk) || (NativeMethods.GetAsyncKeyState((IntPtr)vk) & 0x8000) == 0) continue;
                                    trackedKeys.Add(vk);
                                    if (!TryExchangeCaptureFrame(connection, new CaptureFrame(CaptureSyncDownKind, 0, vk, 0, 0, 0, 0),
                                        140, frameBuffer, replyBuffer, out _))
                                        return;
                                }
                            }
                            Volatile.Write(ref activeHookThreadId, threadId);
                            hooksInstalled = true;
                            readySignaled = true;
                            hooksReady.Set();
                            while (Volatile.Read(ref captureActive) != 0 && NativeMethods.GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
                            {
                                _ = NativeMethods.TranslateMessage(ref msg);
                                _ = NativeMethods.DispatchMessage(ref msg);
                            }
                        }
                        catch (Exception error)
                        {
                            Logger.Log("Privileged capture hook loop ended: " + error.Message);
                        }
                        finally
                        {
                            Volatile.Write(ref activeHookThreadId, 0);
                            Volatile.Write(ref captureActive, 0);
                            if (mouseHook != 0) _ = NativeMethods.UnhookWindowsHookEx(mouseHook);
                            if (keyboardHook != 0) _ = NativeMethods.UnhookWindowsHookEx(keyboardHook);
                            if (!readySignaled)
                            {
                                readySignaled = true;
                                try { hooksReady.Set(); }
                                catch (ObjectDisposedException) { }
                            }
                            GC.KeepAlive(mouseProc);
                            GC.KeepAlive(keyboardProc);
                        }
                    })
                    {
                        IsBackground = true,
                        Priority = System.Threading.ThreadPriority.Highest,
                        Name = "MWBP-PrivilegedCaptureHook",
                    };
                    hookThread.Start();
                    hooksReady.Wait();
                    if (hooksInstalled)
                    {
                        while (!stop.WaitOne(100) && Volatile.Read(ref captureActive) != 0)
                        {
                            if (NativeMethods.WaitForSingleObject(verified.DangerousGetHandle(), 0) == 0) break;
                            if (!PeekNamedPipe(connection.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out _, out _)) break;
                        }
                    }
                    else
                    {
                        backOff = true;
                    }
                }
                catch (Exception error) when (error is IOException or ObjectDisposedException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or ArgumentException)
                {
                }
                finally
                {
                    Volatile.Write(ref server, null);
                    Volatile.Write(ref captureActive, 0);
                    uint tid = Volatile.Read(ref hookThreadId);
                    if (tid != 0) _ = NativeMethods.PostThreadMessage(tid, 0x0012, IntPtr.Zero, IntPtr.Zero);
                    // Close the pipe before joining so blocked capture/flush exchanges unwind immediately.
                    connection.Dispose();
                    hookThread?.Join(1000);
                }
                }
                if (backOff) _ = stop.WaitOne(1000);
            }
        }
        finally
        {
            registered.Unregister(null);
            server?.Dispose();
        }
    }

    private static void RunAgent(string stopEventName, SecurityIdentifier user)
    {
        using var process = Process.GetCurrentProcess();
        process.PriorityClass = ProcessPriorityClass.High;
        int session = process.SessionId;
        agentAllowsApprovalScreens = ApprovalScreensAllowed();
        using var stop = EventWaitHandleAcl.OpenExisting(stopEventName, EventWaitHandleRights.Synchronize);
        NamedPipeServerStream server = null;
        var registered = ThreadPool.RegisterWaitForSingleObject(stop, (_, _) => Volatile.Read(ref server)?.Dispose(), null, Timeout.Infinite, true);
        byte[] bytes = new byte[Marshal.SizeOf<NativeMethods.INPUT64>()];
        byte[] reply = new byte[ReplySize];
        var held = new Dictionary<long, NativeMethods.INPUT64>();
        var injectionDeadline = new InjectionDeadline(TimeSpan.FromSeconds(2), () => Environment.Exit(1));
        InjectionFailure failure = default;
        uint GuardedInject(NativeMethods.INPUT64 input, bool ownedRelease = false) =>
            injectionDeadline.Run(() => InjectWithFailure(input, out failure, ownedRelease));
        bool ReleaseAgentInput()
        {
            InjectionFailure firstFailure = default;
            bool released = ReleaseHeldInput(held, input =>
            {
                uint count = GuardedInject(input, ownedRelease: true); // Held entries are stored as their releases.
                if (count == 0 && firstFailure.Stage == InjectionStage.None) firstFailure = failure;
                return count;
            });
            if (!released) failure = firstFailure;
            return released;
        }
        var captureServer = new System.Threading.Thread(() => RunCaptureServer(stop, user, session))
        {
            IsBackground = true,
            Name = "MWBP-CaptureServer",
        };
        try
        {
            captureServer.Start();
            while (!stop.WaitOne(0))
            {
                using var connection = server = CreateAgentPipe(user, session);
                if (stop.WaitOne(0)) break;
                bool recoveringPreviousConnection = held.Count != 0;
                try
                {
                    connection.WaitForConnection();
                    if (!GetNamedPipeClientProcessId(connection.SafePipeHandle, out uint client)) throw new Win32Exception();
                    using var verified = VerifyExecutable((int)client, session);
                    while (true)
                    {
                        connection.ReadExactly(bytes);
                        var input = MemoryMarshal.Read<NativeMethods.INPUT64>(bytes);
                        if (input.type is not (0 or 1)) throw new InvalidDataException("Only keyboard and mouse input is supported.");
                        if (recoveringPreviousConnection)
                            recoveringPreviousConnection = !ReleaseAgentInput();
                        uint count = recoveringPreviousConnection ? 0
                            : GuardedInject(input, IsPureRelease(input) && IsOwnedRelease(held, input));
                        bool releaseFailed = count == 0 && !recoveringPreviousConnection && IsOwnedRelease(held, input);
                        if (count != 0) TrackHeldInput(held, input);
                        WriteReply(reply, count, held.Count, failure);
                        connection.Write(reply);
                        if (releaseFailed) break;
                    }
                }
                catch (Exception error) when (error is IOException or ObjectDisposedException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or ArgumentException) { }
                finally
                {
                    // Release only inputs owned by this connection, including an interrupted drag.
                    ReleaseAgentInput();
                }
            }
        }
        finally
        {
            registered.Unregister(null);
            server?.Dispose();
            captureServer.Join(1500);
        }
    }

    // A native SendInput call cannot be cancelled by the pipe's 500ms deadline.
    // Retire only its protected worker; SCM already owns restarting the service.
    internal sealed class InjectionDeadline(TimeSpan timeout, Action terminate)
    {
        private readonly object gate = new();
        private object active;
        private bool expired;

        internal uint Run(Func<uint> inject)
        {
            var operation = new object();
            lock (gate)
            {
                if (expired) throw new System.TimeoutException("The input worker has expired.");
                active = operation;
            }
            using var timer = new System.Threading.Timer(_ => Expire(operation), null, timeout, Timeout.InfiniteTimeSpan);
            try
            {
                uint count = inject();
                lock (gate)
                {
                    if (expired) throw new System.TimeoutException("The input worker has expired.");
                    active = null;
                }
                return count;
            }
            finally { lock (gate) { if (ReferenceEquals(active, operation)) active = null; } }
        }

        private void Expire(object operation)
        {
            lock (gate)
            {
                if (!ReferenceEquals(active, operation)) return;
                expired = true;
                active = null;
                terminate();
            }
        }
    }

    private static bool ReleaseHeldInput(Dictionary<long, NativeMethods.INPUT64> held, Func<NativeMethods.INPUT64, uint> inject)
    {
        // Desktop transitions can reject an UP. Keep its ownership until an UP actually succeeds.
        foreach (var entry in new List<KeyValuePair<long, NativeMethods.INPUT64>>(held))
            if (inject(entry.Value) != 0) held.Remove(entry.Key);
        return held.Count == 0;
    }

    internal static void TrackHeldInput(Dictionary<long, NativeMethods.INPUT64> held, NativeMethods.INPUT64 input)
    {
        if (input.type == 1)
        {
            long key = KeyIdentity(input);
            if ((input.ki.dwFlags & (int)NativeMethods.KEYEVENTF.KEYUP) != 0) held.Remove(key);
            else { input.ki.dwFlags |= (int)NativeMethods.KEYEVENTF.KEYUP; held[key] = input; }
            return;
        }
        for (int i = 0; i < MouseButtons.Length; i++)
        {
            var (down, up, data) = MouseButtons[i];
            if (data != 0 && (input.mi.mouseData & data) == 0) continue;
            if ((input.mi.dwFlags & up) != 0) held.Remove(-i - 1);
            else if ((input.mi.dwFlags & down) != 0)
            {
                var release = input; release.mi.dwFlags = up; release.mi.mouseData = data;
                held[-i - 1] = release;
            }
        }
    }

    private static long KeyIdentity(NativeMethods.INPUT64 input) => ((long)(ushort)input.ki.wVk << 17)
        | ((long)(ushort)input.ki.wScan << 1) | ((input.ki.dwFlags & (int)NativeMethods.KEYEVENTF.EXTENDEDKEY) != 0 ? 1L : 0L);

    private static bool IsOwnedRelease(Dictionary<long, NativeMethods.INPUT64> held, NativeMethods.INPUT64 input)
    {
        if (input.type == 1) return (input.ki.dwFlags & (int)NativeMethods.KEYEVENTF.KEYUP) != 0 && held.ContainsKey(KeyIdentity(input));
        for (int i = 0; i < MouseButtons.Length; i++)
        {
            var (_, up, data) = MouseButtons[i];
            if ((input.mi.dwFlags & up) != 0 && (data == 0 || (input.mi.mouseData & data) != 0) && held.ContainsKey(-i - 1)) return true;
        }
        return false;
    }

    private static uint Inject(NativeMethods.INPUT64 input) => InjectWithFailure(input, out _);

    private static uint InjectWithFailure(NativeMethods.INPUT64 input, out InjectionFailure failure, bool ownedRelease = false)
    {
        failure = default;
        IntPtr original = NativeMethods.GetThreadDesktop(NativeMethods.GetCurrentThreadId());
        IntPtr desktop = NativeMethods.OpenInputDesktop(0, false, NativeMethods.DESKTOP_READOBJECTS | NativeMethods.DESKTOP_WRITEOBJECTS | DesktopJournalPlayback);
        if (desktop == IntPtr.Zero) { failure = new(InjectionStage.OpenDesktop, Marshal.GetLastWin32Error()); return 0; }
        try
        {
            if (!ownedRelease && IsBlockedDesktop(desktop)) { failure = new(InjectionStage.ApprovalScreenBlocked, 5); return 0; }
            if (!SetThreadDesktop(desktop)) { failure = new(InjectionStage.AttachDesktop, Marshal.GetLastWin32Error()); return 0; }
            if (input.type == 0) input.mi.dwExtraInfo = InputSimulation.InjectedInputTag;
            else input.ki.dwExtraInfo = InputSimulation.InjectedInputTag;
            uint count = NativeMethods.SendInput64(1, [input], Marshal.SizeOf(input));
            if (count == 0) failure = new(InjectionStage.SendInput, Marshal.GetLastWin32Error());
            return count;
        }
        finally
        {
            // A blocked desktop was never attached, so there is nothing to restore.
            if (failure.Stage != InjectionStage.ApprovalScreenBlocked && !SetThreadDesktop(original) && failure.Stage == InjectionStage.None)
                failure = new(InjectionStage.RestoreDesktop, Marshal.GetLastWin32Error());
            CloseDesktop(desktop);
        }
    }

    private sealed class InputService : ServiceBase
    {
        private readonly object gate = new();
        private Process agent;
        private EventWaitHandle stopAgent;
        private EventWaitHandle handoff;
        private Timer retry;
        private bool logonAgent;
        private bool stopping;
        internal InputService() { ServiceName = PrivilegedInput.ServiceName; CanHandleSessionChangeEvent = true; AutoLog = false; }
        protected override void OnStart(string[] args) => retry = new Timer(_ => TryEnsureAgent(), null, 0, 2000);

        private void TryEnsureAgent()
        {
            try { EnsureAgent(); }
            catch (Exception error) when (error is IOException or Win32Exception or UnauthorizedAccessException)
            { Logger.Log("Input session launch will retry: " + error.GetType().Name); }
        }
        protected override void OnSessionChange(SessionChangeDescription changeDescription)
        {
            if (changeDescription.Reason == SessionChangeReason.SessionLogoff)
            {
                lock (gate)
                    if (agent != null && agent.SessionId == changeDescription.SessionId) StopAgent();
                return; // The timer waits for the next input desktop/session to become ready.
            }
            TryEnsureAgent();
        }
        protected override void OnStop() { lock (gate) { stopping = true; retry?.Dispose(); StopAgent(); } }
        private void AgentExited(object sender, EventArgs args)
        {
            lock (gate)
            {
                if (stopping || !ReferenceEquals(sender, agent)) return;
                if (!logonAgent) Environment.Exit(1);
                Logger.Log("Sign-in input process exited: " + agent.ExitCode);
                StopAgent();
            }
        }
        private void StopAgent()
        {
            if (agent != null)
            {
                agent.Exited -= AgentExited;
                stopAgent?.Set();
                if (!agent.HasExited && !agent.WaitForExit(5000))
                {
                    try { agent.Kill(); }
                    catch (InvalidOperationException) when (agent.HasExited) { }
                    if (!agent.WaitForExit(5000)) throw new IOException("The previous input process is still running.");
                }
                agent.Dispose(); agent = null;
            }
            stopAgent?.Dispose(); stopAgent = null;
            handoff?.Dispose(); handoff = null;
        }
        private void EnsureAgent()
        {
            lock (gate)
            {
                int session = (int)NativeMethods.WTSGetActiveConsoleSessionId();
                if (stopping) return;
                if (!ServiceModeAllowed) { StopAgent(); return; }
                string authorized = AuthorizedUserSid();
                SecurityIdentifier user = null;
                // Original MWB launches a SYSTEM process on winlogon before a user token exists.
                if (session != -1)
                    try { user = InteractiveUser(session); } catch (Win32Exception) { }
                bool approvalScreens = ApprovalScreensAllowed();
                string role = LogonSession.SelectRole(authorized, user?.Value, session, approvalScreens);
                if (role == null)
                { StopAgent(); return; }
                bool needsLogon = role == LogonSession.Argument;
                if (agent != null && !agent.HasExited && agent.SessionId == session)
                {
                    if (logonAgent == needsLogon) return;
                    if (logonAgent && approvalScreens && handoff != null && !handoff.WaitOne(0)) return;
                }
                StopAgent();
                string eventName = @"Global\MWBP.Input.Stop." + Guid.NewGuid().ToString("N");
                var security = new EventWaitHandleSecurity();
                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.SetAccessRuleProtection(true, false); security.SetOwner(system);
                security.AddAccessRule(new EventWaitHandleAccessRule(system, EventWaitHandleRights.FullControl, AccessControlType.Allow));
                stopAgent = EventWaitHandleAcl.Create(false, EventResetMode.ManualReset, eventName, out bool created, security);
                if (!created) throw new IOException("The input stop signal already exists.");
                logonAgent = needsLogon;
                if (needsLogon) handoff = LogonSession.CreateHandoff(session, new SecurityIdentifier(authorized));
                agent = LaunchAgent(session, eventName, user ?? new SecurityIdentifier(authorized), needsLogon);
                agent.Exited += AgentExited;
                agent.EnableRaisingEvents = true;
            }
        }
    }

    // Adapted from Microsoft PowerToys App/Service/NativeMethods.cs: keep only session launch.
    private static Process LaunchAgent(int session, string stopEventName, SecurityIdentifier user, bool logon = false)
    {
        using var winlogon = Array.Find(Process.GetProcessesByName("winlogon"), process => process.SessionId == session)
            ?? throw new IOException("The console session is not ready.");
        IntPtr process = IntPtr.Zero, token = IntPtr.Zero, duplicate = IntPtr.Zero;
        NativeMethods.PROCESS_INFORMATION launched = default;
        try
        {
            process = NativeMethods.OpenProcess(0x1000, false, (uint)winlogon.Id);
            if (process == IntPtr.Zero || !NativeMethods.OpenProcessToken(process, NativeMethods.TOKEN_DUPLICATE | NativeMethods.TOKEN_QUERY, ref token)) throw new Win32Exception();
            var attributes = new NativeMethods.SECURITY_ATTRIBUTES { Length = Marshal.SizeOf<NativeMethods.SECURITY_ATTRIBUTES>() };
            if (!NativeMethods.DuplicateTokenEx(token, NativeMethods.MAXIMUM_ALLOWED, ref attributes, 2, 1, ref duplicate)) throw new Win32Exception();
            string access = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00101000;;;" + user.Value + ")";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(access, 1, out attributes.lpSecurityDescriptor, out _)) throw new Win32Exception();
            var threadAttributes = new NativeMethods.SECURITY_ATTRIBUTES { Length = Marshal.SizeOf<NativeMethods.SECURITY_ATTRIBUTES>() };
            var startup = new NativeMethods.STARTUPINFO { cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>(), lpDesktop = logon ? @"winsta0\winlogon" : @"winsta0\default" };
            string command = '"' + ProtectedExecutable + '"' + " " + (logon ? LogonSession.Argument : AgentArgument) + " " + stopEventName + " " + user.Value;
            try
            {
                if (!NativeMethods.CreateProcessAsUser(duplicate, ProtectedExecutable, command, ref attributes, ref threadAttributes, false, 0,
                    IntPtr.Zero, ProtectedDirectory, ref startup, out launched)) throw new Win32Exception();
                return Process.GetProcessById((int)launched.dwProcessId);
            }
            finally { LocalFree(attributes.lpSecurityDescriptor); }
        }
        finally
        {
            if (launched.hProcess != IntPtr.Zero) NativeMethods.CloseHandle(launched.hProcess);
            if (launched.hThread != IntPtr.Zero) NativeMethods.CloseHandle(launched.hThread);
            if (duplicate != IntPtr.Zero) NativeMethods.CloseHandle(duplicate);
            if (token != IntPtr.Zero) NativeMethods.CloseHandle(token);
            if (process != IntPtr.Zero) NativeMethods.CloseHandle(process);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string descriptor, uint revision, out IntPtr security, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool PeekNamedPipe(SafePipeHandle pipe, IntPtr buffer, uint bufferSize, IntPtr bytesRead, out uint totalBytesAvail, out uint bytesLeftThisMessage);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool CloseDesktop(IntPtr desktop);
    // Unicode marshalling is required: the default would read the UTF-16 name back as ANSI.
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetUserObjectInformation(IntPtr handle, int index, [Out] char[] information, int length, out int needed);
}

