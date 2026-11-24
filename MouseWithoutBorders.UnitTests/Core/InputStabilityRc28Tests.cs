using System.Drawing;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.PowerToys.Settings.UI.Library;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MouseWithoutBorders.Class;
using MouseWithoutBorders.Core;

namespace MouseWithoutBorders.UnitTests.Core;

[TestClass]
[DoNotParallelize]
public sealed class InputStabilityRc28Tests
{
    private const BindingFlags StaticFields = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
    private const BindingFlags InstanceFields = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;

    private readonly List<(FieldInfo Field, object? Owner, object? Value)> saved = new();
    private MouseWithoutBorders.Class.Settings originalSettings = null!;
    private MouseWithoutBorders.Class.Settings synthetic = null!;
    private SocketStuff originalTransport = null!;
    private ID originalDestination, originalNewDestination;
    private Point originalPosition;
    private string originalName = null!;
    private int originalPaintCount;
    private int originalSwitchCount;
    private System.Diagnostics.Process originalProcess = null!, ownedProcess = null!;
    private string folder = null!;

    [TestInitialize]
    public void Setup()
    {
        originalSettings = Setting.Values;
        originalTransport = Common.Sk;
        originalProcess = Common.CurrentProcess;
        Common.CurrentProcess = ownedProcess = System.Diagnostics.Process.GetCurrentProcess();
        originalDestination = MachineStuff.desMachineID;
        originalNewDestination = MachineStuff.newDesMachineID;
        originalPosition = Common.LastPos;
        originalPaintCount = Common.PaintCount;
        originalSwitchCount = MachineStuff.SwitchLocation.Count;
        originalName = Common.MachineName;
        Common.MachineName = "A";

        var matrix = typeof(MachineStuff).GetField("mcMatrix", StaticFields)!;
        saved.Add((matrix, null, matrix.GetValue(null)));
        matrix.SetValue(null, null);
        foreach (var type in new[] { typeof(Event), typeof(InputHook), typeof(DragDrop), typeof(Package), typeof(MonitorTopology), typeof(Receiver) })
            foreach (var field in type.GetFields(StaticFields).Where(field => !field.IsInitOnly && !field.IsLiteral))
                saved.Add((field, null, field.GetValue(null)));
        var packet = typeof(Event).GetField("MousePackage", StaticFields)!.GetValue(null)!;
        foreach (var field in typeof(DATA).GetFields(InstanceFields))
            saved.Add((field, packet, field.GetValue(packet)));
        ((DATA)packet).Src = ID.NONE;

        folder = Path.Combine(Path.GetTempPath(), "mwb-rc28-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var document = new MouseWithoutBordersSettings();
        document.Properties.SecurityKey.Value = "synthetic-rc28-key";
        document.Properties.MachineID.Value = 101;
        document.Properties.TransferFile = false;
        document.Properties.MachineMatrixString = ["A", "B", "", ""];
        string path = Path.Combine(folder, "prefs.json");
        PortableSettingsStore.Write(path, JsonSerializer.Serialize(document, SettingsUtils.SerializerOptions));
        synthetic = new MouseWithoutBorders.Class.Settings(new SettingsUtils(path), false);
        Setting.Values = synthetic;

        var state = typeof(MonitorTopology).GetField("state", StaticFields)!;
        state.SetValue(null, Activator.CreateInstance(state.FieldType, InstanceFields, null,
            [new Dictionary<uint, MonitorDescriptor[]>(), Array.Empty<MonitorOrigin>(), Array.Empty<uint>(), 0u, new MonitorLayout([])], null));
        MonitorTopology.AcceptPeer(101, [new("A1", 0, 0, 2560, 1440)]);
        MonitorTopology.AcceptPeer(202, [new("B1", 0, 0, 2560, 1440)]);
        MonitorTopology.ApplyOrigins([new(101, "A1", 0, 0), new(202, "B1", 2560, 0)]);
        Common.Sk = null!;
        DragDrop.IsDragging = false;
        DragDrop.IsDropping = false;
    }

    [TestCleanup]
    public void Cleanup()
    {
        try { synthetic?.SaveSettingsSynchronously(); }
        finally
        {
            Setting.Values = originalSettings;
            Common.Sk = originalTransport;
            Common.CurrentProcess = originalProcess;
            ownedProcess.Dispose();
            MachineStuff.desMachineID = originalDestination;
            MachineStuff.newDesMachineID = originalNewDestination;
            Common.LastPos = originalPosition;
            Common.PaintCount = originalPaintCount;
            MachineStuff.SwitchLocation.Count = originalSwitchCount;
            Common.MachineName = originalName;
            foreach (var value in saved) value.Field.SetValue(value.Owner, value.Value);
            Directory.Delete(folder, true);
        }
    }

    [TestMethod]
    public void PrivilegedCaptureFrameRoundTripPreservesCoordinatesAndTags()
    {
        byte[] buffer = new byte[PrivilegedInput.CaptureFrameSize];
        var mouse = new PrivilegedInput.CaptureFrame(0, WM.WM_MOUSEWHEEL, -2560, -1440, 120 << 16, 1, InputSimulation.InjectedInputTag.ToInt64());
        PrivilegedInput.WriteCaptureFrame(buffer, mouse);
        Assert.AreEqual(mouse, PrivilegedInput.ReadCaptureFrame(buffer));

        var keyboard = new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureKeyboardKind, WM.WM_KEYDOWN, 0x14, 0x3A, 0x10, 4242, 0x43524430);
        PrivilegedInput.WriteCaptureFrame(buffer, keyboard);
        Assert.AreEqual(keyboard, PrivilegedInput.ReadCaptureFrame(buffer));

        var ghostRelease = new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureGhostReleaseKind, 0, 0x14, 0, 0, 0, 0);
        PrivilegedInput.WriteCaptureFrame(buffer, ghostRelease);
        Assert.AreEqual(ghostRelease, PrivilegedInput.ReadCaptureFrame(buffer));

        var syncDown = new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureSyncDownKind, 0, (int)VK.LCONTROL, 0, 0, 0, 0);
        PrivilegedInput.WriteCaptureFrame(buffer, syncDown);
        Assert.AreEqual(syncDown, PrivilegedInput.ReadCaptureFrame(buffer));

        // Aggregate generic VKs and mouse virtual keys must never be seeded on SYSTEM startup sync.
        Assert.IsFalse(PrivilegedInput.ShouldSeedPhysicalKey(0x10)); // VK_SHIFT
        Assert.IsFalse(PrivilegedInput.ShouldSeedPhysicalKey(0x11)); // VK_CONTROL
        Assert.IsFalse(PrivilegedInput.ShouldSeedPhysicalKey(0x12)); // VK_MENU
        Assert.IsFalse(PrivilegedInput.ShouldSeedPhysicalKey(0x01)); // VK_LBUTTON
        Assert.IsTrue(PrivilegedInput.ShouldSeedPhysicalKey(0x14));  // VK_CAPITAL (Caps Lock)
        Assert.IsTrue(PrivilegedInput.ShouldSeedPhysicalKey((int)VK.RCONTROL));
    }

    [TestMethod]
    public void SuppressedRemoteKeysStayOffGetAsyncKeyStatePruningSoEmergencyChordAlwaysWorks()
    {
        var held = (HeldKeyChord)typeof(InputHook).GetField("easyMouseKeys", StaticFields)!.GetValue(null)!;
        var previousKeys = held.DownKeys;
        var hook = (InputHook)RuntimeHelpers.GetUninitializedObject(typeof(InputHook));
        GC.SuppressFinalize(hook);
        var liveKeysField = typeof(InputHook).GetField("livePhysicalKeys", InstanceFields)!;
        var localModifiersField = typeof(InputHook).GetField("localModifiers", InstanceFields)!;
        var hKeyboardHookField = typeof(InputHook).GetField("hKeyboardHook", InstanceFields)!;
        var emergencyField = typeof(InputHook).GetField("emergencyBackspaceDown", InstanceFields)!;
        try
        {
            held.Clear();
            liveKeysField.SetValue(hook, new HashSet<int>());
            hKeyboardHookField.SetValue(hook, 1); // Simulate active local hook path without privileged pipe.
            synthetic.KeyboardShortcutsEnabled = false;
            MachineStuff.desMachineID = MachineStuff.newDesMachineID = (ID)202; // Controlling peer: physical keys suppressed.
            hook.KeyboardEvent += _ => { };

            // Suppressed remote Ctrl + Alt must stay held in easyMouseKeys and NOT enter livePhysicalKeys
            // (because OS GetAsyncKeyState stays 0 for suppressed keys), allowing Backspace to trigger emergency return.
            Assert.IsTrue(hook.ProcessKeyboardHookData(WM.WM_KEYDOWN, (int)VK.LCONTROL, 0x1D, 0, 10, IntPtr.Zero));
            var liveKeys = (HashSet<int>)liveKeysField.GetValue(hook)!;
            Assert.IsFalse(liveKeys.Contains((int)VK.LCONTROL), "Suppressed remote key-down must not enter GetAsyncKeyState pruning set.");
            Assert.AreEqual((byte)0, (byte)localModifiersField.GetValue(hook)!);

            // Simulated reconcile (GetAsyncKeyState == 0 on all keys) before Alt arrives must NOT prune remote Ctrl.
            hook.ReconcileHeldKeys(_ => false, activeDownVk: (int)VK.LMENU);
            Assert.IsTrue(held.IsActive(EasyMouseOption.Ctrl, Array.Empty<int>()), "Held remote Ctrl must survive before Alt arrives.");

            Assert.IsTrue(hook.ProcessKeyboardHookData(WM.WM_KEYDOWN, (int)VK.LMENU, 0x38, 0, 20, IntPtr.Zero));
            Assert.IsTrue(held.IsActive(EasyMouseOption.Ctrl, Array.Empty<int>()));
            Assert.IsTrue(held.IsActive(EasyMouseOption.Alt, Array.Empty<int>()));

            // Emergency Ctrl+Alt+Backspace restores local control immediately.
            Assert.IsTrue(hook.ProcessKeyboardHookData(WM.WM_KEYDOWN, (int)VK.BACK, 0x0E, 0, 30, IntPtr.Zero));
            Assert.AreEqual((ID)101, Common.DesMachineID);
            Assert.IsTrue((bool)emergencyField.GetValue(hook)!);
        }
        finally
        {
            hKeyboardHookField.SetValue(hook, 0);
            emergencyField.SetValue(hook, false);
            held.Clear();
            foreach (int key in previousKeys) held.Update(key, true);
        }
    }

    [TestMethod]
    public void PrivilegedCapturePreservesHeldActivationAcrossMouseAndKeyboardAndReleasesExplicitGhostFrame()
    {
        var held = (HeldKeyChord)typeof(InputHook).GetField("easyMouseKeys", StaticFields)!.GetValue(null)!;
        var previousKeys = held.DownKeys;
        var hook = (InputHook)RuntimeHelpers.GetUninitializedObject(typeof(InputHook));
        GC.SuppressFinalize(hook);
        var privilegedActiveField = typeof(InputHook).GetField("privilegedCaptureActive", InstanceFields)!;
        var liveKeysField = typeof(InputHook).GetField("livePhysicalKeys", InstanceFields)!;
        var localModifiersField = typeof(InputHook).GetField("localModifiers", InstanceFields)!;
        var activationPendingField = typeof(Event).GetField("activationPending", StaticFields)!;
        try
        {
            held.Clear();
            liveKeysField.SetValue(hook, new HashSet<int>());
            privilegedActiveField.SetValue(hook, true);
            synthetic.EasyMouse = (int)EasyMouseOption.Custom;
            synthetic.EasyMouseActivationKeys = [0x14];
            synthetic.KeyboardShortcutsEnabled = false;
            MachineStuff.desMachineID = MachineStuff.newDesMachineID = (ID)101;
            Event.SetMouseSwitchActivation(false);
            hook.KeyboardEvent += _ => { };

            // Even when Medium-IL GetAsyncKeyState would return 0 over elevated windows,
            // privileged capture must retain held keys across WM_MOUSEMOVE and additional keys.
            Assert.IsFalse(hook.DispatchCaptureFrame(new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureSyncDownKind, 0, (int)VK.LCONTROL, 0, 0, 0, 0)));
            Assert.IsFalse(hook.DispatchCaptureFrame(new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureKeyboardKind, WM.WM_KEYDOWN, 0x14, 0x3A, 0, 10, 0)));
            Assert.IsTrue(InputHook.CtrlDown);
            Assert.IsTrue(InputHook.EasyMouseKeyDown);
            Assert.IsTrue((bool)activationPendingField.GetValue(null)!);

            Assert.IsFalse(hook.DispatchCaptureFrame(new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureMouseKind, WM.WM_MOUSEMOVE, 100, 100, 0, 0, 0)));
            Assert.IsTrue(InputHook.CtrlDown);
            Assert.IsTrue(InputHook.EasyMouseKeyDown, "Privileged mouse moves must not prune held activation via Medium-IL GetAsyncKeyState.");
            Assert.IsTrue((bool)activationPendingField.GetValue(null)!);

            Assert.IsFalse(hook.DispatchCaptureFrame(new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureKeyboardKind, WM.WM_KEYDOWN, (int)VK.LMENU, 0x38, 0, 20, 0)));
            Assert.IsTrue(InputHook.CtrlDown);
            Assert.IsTrue(InputHook.EasyMouseKeyDown);

            // Explicit SYSTEM ghost release removes only the missed key cleanly.
            Assert.IsFalse(hook.DispatchCaptureFrame(new PrivilegedInput.CaptureFrame(PrivilegedInput.CaptureGhostReleaseKind, 0, 0x14, 0, 0, 0, 0)));
            Assert.IsFalse(InputHook.EasyMouseKeyDown);
            Assert.IsFalse((bool)activationPendingField.GetValue(null)!);
            Assert.IsTrue(InputHook.CtrlDown);
            Assert.AreNotEqual((byte)0, (byte)localModifiersField.GetValue(hook)!);
        }
        finally
        {
            privilegedActiveField.SetValue(hook, false);
            held.Clear();
            foreach (int key in previousKeys) held.Update(key, true);
        }
    }

    [TestMethod]
    public async Task PrivilegedCaptureExchangeForwardsReplyAndFailsOpenOnTimeout()
    {
        string pipeName = "mwb-capture-test-" + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync();
        await client.ConnectAsync(2000);
        await accept;

        var first = new PrivilegedInput.CaptureFrame(0, WM.WM_MOUSEMOVE, 123, 456, 0, 0, 0);
        var second = new PrivilegedInput.CaptureFrame(1, WM.WM_KEYDOWN, 0x14, 0, 0, 1, 0);
        var clientTask = Task.Run(async () =>
        {
            byte[] buf = new byte[PrivilegedInput.CaptureFrameSize];
            await client.ReadExactlyAsync(buf);
            Assert.AreEqual(first, PrivilegedInput.ReadCaptureFrame(buf));
            await client.WriteAsync(new byte[] { 1 });

            await client.ReadExactlyAsync(buf);
            Assert.AreEqual(second, PrivilegedInput.ReadCaptureFrame(buf));
            await client.WriteAsync(new byte[] { 0 });

            await client.ReadExactlyAsync(buf); // Deliberately omit reply to exercise timeout.
        });

        Assert.IsTrue(PrivilegedInput.TryExchangeCaptureFrame(server, first, 1000, out bool suppressFirst));
        Assert.IsTrue(suppressFirst);
        Assert.IsTrue(PrivilegedInput.TryExchangeCaptureFrame(server, second, 1000, out bool suppressSecond));
        Assert.IsFalse(suppressSecond);

        bool completed = PrivilegedInput.TryExchangeCaptureFrame(server, first, 60, out bool suppressTimeout);
        Assert.IsFalse(completed);
        Assert.IsFalse(suppressTimeout, "Timed-out privileged capture exchange must fail open to local input.");
        server.Dispose();
        await clientTask;
    }

    [TestMethod]
    public void ReconcileHeldKeysPrunesGhostKeysAndRestoresShortcutMatching()
    {
        var held = (HeldKeyChord)typeof(InputHook).GetField("easyMouseKeys", StaticFields)!.GetValue(null)!;
        var previousKeys = held.DownKeys;
        var hook = (InputHook)RuntimeHelpers.GetUninitializedObject(typeof(InputHook));
        GC.SuppressFinalize(hook);
        var localModifiersField = typeof(InputHook).GetField("localModifiers", InstanceFields)!;
        var activationPendingField = typeof(Event).GetField("activationPending", StaticFields)!;
        try
        {
            held.Clear();
            synthetic.EasyMouse = (int)EasyMouseOption.Custom;
            synthetic.EasyMouseActivationKeys = [0x14];
            MachineStuff.desMachineID = MachineStuff.newDesMachineID = (ID)101;
            Event.SetMouseSwitchActivation(false);

            var processKey = typeof(InputHook).GetMethod("ProcessKeyEx", InstanceFields)!;
            _ = processKey.Invoke(hook, [(int)VK.LCONTROL, 0, new KEYBDDATA { wVk = (short)VK.LCONTROL }]);
            _ = processKey.Invoke(hook, [0x14, 0, new KEYBDDATA { wVk = 0x14 }]);
            localModifiersField.SetValue(hook, (byte)4);

            Assert.IsTrue(InputHook.CtrlDown);
            Assert.IsTrue(InputHook.EasyMouseKeyDown);
            Assert.IsTrue((bool)activationPendingField.GetValue(null)!);

            // Simulate Caps Lock (0x14) physically released across a missed KEYUP while LControl remains down.
            hook.ReconcileHeldKeys(vk => vk == (int)VK.LCONTROL, activeDownVk: (int)VK.LMENU);
            CollectionAssert.AreEqual(new[] { (int)VK.LCONTROL }, held.DownKeys);
            Assert.IsTrue(InputHook.CtrlDown);
            Assert.IsFalse(InputHook.EasyMouseKeyDown);
            Assert.IsFalse((bool)activationPendingField.GetValue(null)!);

            // Releasing LControl physically without KEYUP must also clear CtrlDown and localModifiers.
            hook.ReconcileHeldKeys(_ => false);
            Assert.AreEqual(0, held.DownKeys.Length);
            Assert.IsFalse(InputHook.CtrlDown);
            Assert.AreEqual((byte)0, (byte)localModifiersField.GetValue(hook)!);
            Assert.IsTrue(held.Update(0x52, true)); // Fresh shortcut key alone matches exact without ghost Caps/Ctrl.
            Assert.IsTrue(held.MatchesExact([0x52]));
        }
        finally
        {
            held.Clear();
            foreach (int key in previousKeys) held.Update(key, true);
        }
    }

    [TestMethod]
    public void VisibleRelativePointerSyncRequiresVisibleUnclippedCursor()
    {
        var monitor = new Rectangle(0, 0, 2560, 1440);
        var virtualDesktop = new Rectangle(-2560, -1440, 5120, 2880);
        var confinedGameWindow = new Rectangle(100, 100, 1280, 720);

        Assert.IsTrue(Receiver.CanSyncVisibleRelativePointer(true, virtualDesktop, monitor));
        Assert.IsFalse(Receiver.CanSyncVisibleRelativePointer(false, virtualDesktop, monitor), "Hidden 3D game cursors must stay purely relative.");
        Assert.IsFalse(Receiver.CanSyncVisibleRelativePointer(true, confinedGameWindow, monitor), "Clipped game cursors must not sync edge offsets.");
        Assert.IsFalse(Receiver.CanSyncVisibleRelativePointer(true, virtualDesktop, Rectangle.Empty));
    }

    [TestMethod]
    public void RelativeCursorSyncCorrectsDriftedShadowPointerAtEdgeWhilePreservingHiddenGameBehavior()
    {
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(listener.LocalEndPoint!);
        using var accepted = listener.Accept();
        using var wire = new MemoryStream();
        using var peer = new TcpSk(false, socket, SocketStatus.Connected, "B") { MachineId = 202 };
        typeof(TcpSk).GetField("encryptedStream", InstanceFields)!.SetValue(peer, wire);
        var transport = (SocketStuff)RuntimeHelpers.GetUninitializedObject(typeof(SocketStuff));
        transport.TcpSocketsLock = new object();
        typeof(SocketStuff).GetProperty("TcpSockets", InstanceFields)!.SetValue(transport, new List<TcpSk> { peer });
        Common.Sk = transport;

        var held = (HeldKeyChord)typeof(InputHook).GetField("easyMouseKeys", StaticFields)!.GetValue(null)!;
        var previousKeys = held.DownKeys;
        var nativePosition = Point.Empty;
        bool canRestorePosition = NativeMethods.GetCursorPos(ref nativePosition);
        var hook = (InputHook)RuntimeHelpers.GetUninitializedObject(typeof(InputHook));
        GC.SuppressFinalize(hook);
        hook.MouseEvent += Event.MouseEvent;
        hook.KeyboardEvent += _ => { };
        try
        {
            held.Clear();
            held.Update(0x14, true); // Caps Lock held.
            synthetic.EasyMouse = (int)EasyMouseOption.Custom;
            synthetic.EasyMouseActivationKeys = [0x14];
            synthetic.MoveMouseRelatively = true;
            MachineStuff.desMachineID = MachineStuff.newDesMachineID = (ID)202;
            typeof(Event).GetField("activeMonitor", StaticFields)!.SetValue(null, new MonitorKey(202, "B1"));
            var pointerField = typeof(Event).GetField("monitorPoint", StaticFields)!;
            pointerField.SetValue(null, new Point(1200, 700)); // Drifted far from left edge.
            Common.LastPos = new Point(500, 500);

            // Legacy RC19/20 PointerCapture (WheelDelta == 0) and hidden-cursor game play leave monitorPoint untouched.
            var legacyCapture = new DATA { Type = PackageType.PointerCapture, Src = (ID)202, Des = (ID)101, Id = 5001 };
            legacyCapture.Md.X = 1;
            legacyCapture.Md.Y = 700;
            Receiver.ProcessPackage(legacyCapture, peer);
            Event.MouseEvent(new MOUSEDATA { dwFlags = WM.WM_MOUSEMOVE, X = 495, Y = 500 }, -5, 0);
            Assert.AreEqual((ID)202, Common.DesMachineID);
            Assert.AreEqual(new Point(1195, 700), (Point)pointerField.GetValue(null)!);

            // Visible cursor sync reports real OS position (1, 700) on peer B1; dx=-5 crosses back to A1 cleanly.
            var sync = new DATA { Type = PackageType.PointerCapture, Src = (ID)202, Des = (ID)101, Id = 5002 };
            sync.Md.X = 1;
            sync.Md.Y = 700;
            sync.Md.WheelDelta = Event.RelativeCursorSyncTag;
            Receiver.ProcessPackage(sync, peer);
            Event.MouseEvent(new MOUSEDATA { dwFlags = WM.WM_MOUSEMOVE, X = 490, Y = 500 }, -5, 0);
            Assert.AreEqual((ID)101, Common.DesMachineID, "Synced edge pointer must return control to the local PC.");
        }
        finally
        {
            peer.InputWriter?.Stop();
            held.Clear();
            foreach (int key in previousKeys) held.Update(key, true);
            if (canRestorePosition) NativeMethods.SetCursorPos(nativePosition.X, nativePosition.Y);
        }
    }

    [TestMethod]
    public void NullForegroundAndMaximizedTitledWindowAvoidFalseProtectionAndFullscreenBlock()
    {
        Assert.IsFalse(ForegroundInputAccess.NullForegroundRequiresBroker(inputDesktopAccessible: true));
        Assert.IsTrue(ForegroundInputAccess.NullForegroundRequiresBroker(inputDesktopAccessible: false));

        const long wsCaption = 0x00C00000L;
        const long wsPopup = unchecked((int)0x80000000);
        Assert.IsTrue(Common.IsMaximizedTitledWindow(isZoomed: true, windowStyle: wsCaption | 0x01000000L));
        Assert.IsFalse(Common.IsMaximizedTitledWindow(isZoomed: false, windowStyle: wsCaption));
        Assert.IsFalse(Common.IsMaximizedTitledWindow(isZoomed: true, windowStyle: wsPopup));

        var assist = FormHelper.CreateForegroundAssistInput64();
        Assert.AreEqual(0, assist.type);
        Assert.AreEqual(InputSimulation.InjectedInputTag, assist.mi.dwExtraInfo);
        Assert.AreEqual(40, Marshal.SizeOf(assist));
    }

    [TestMethod]
    public void PrivilegedCaptureSkipsSecureDesktopsAndDefersUpgradeWhileControllingRemotePeer()
    {
        var hook = (InputHook)RuntimeHelpers.GetUninitializedObject(typeof(InputHook));
        GC.SuppressFinalize(hook);
        bool oldLogon = Common.RunOnLogonDesktop;
        bool oldScrSaver = Common.RunOnScrSaverDesktop;
        var tryStart = typeof(InputHook).GetMethod("TryStartPrivilegedCapture", InstanceFields)!;
        try
        {
            MachineStuff.desMachineID = MachineStuff.newDesMachineID = (ID)202;
            Assert.IsFalse(hook.TryUpgradePrivilegedCapture(), "Capture upgrade must defer while controlling a remote peer.");

            Common.RunOnLogonDesktop = true;
            Assert.IsFalse((bool)tryStart.Invoke(hook, null)!, "Logon desktop must not bind to the Default-desktop agent capture pipe.");
            Common.RunOnLogonDesktop = false;

            Common.RunOnScrSaverDesktop = true;
            Assert.IsFalse((bool)tryStart.Invoke(hook, null)!, "Screen-saver desktop must not bind to the Default-desktop agent capture pipe.");
        }
        finally
        {
            Common.RunOnLogonDesktop = oldLogon;
            Common.RunOnScrSaverDesktop = oldScrSaver;
        }
    }
}
