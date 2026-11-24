// Copyright (c) Microsoft Corporation
// The Microsoft Corporation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

// <summary>
//     Keyboard/Mouse hook callbacks, pre-process before calling to routines in Common.Event.
// </summary>
// <history>
//     2008 created by Truong Do (ductdo).
//     2009-... modified by Truong Do (TruongDo).
//     2023- Included in PowerToys.
// </history>
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

using Microsoft.PowerToys.Settings.UI.Library;
using MouseWithoutBorders.Core;

[module: SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes", Scope = "member", Target = "MouseWithoutBorders.InputHook.#MouseHookProc(System.Int32,System.Int32,System.IntPtr)", Justification = "Dotnet port with style preservation")]
[module: SuppressMessage("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity", Scope = "member", Target = "MouseWithoutBorders.InputHook.#ProcessKeyEx(System.Int32,System.Int32)", Justification = "Dotnet port with style preservation")]
[module: SuppressMessage("Microsoft.Globalization", "CA1300:SpecifyMessageBoxOptions", Scope = "member", Target = "MouseWithoutBorders.InputHook.#Start()", Justification = "Dotnet port with style preservation")]

namespace MouseWithoutBorders.Class
{
    internal partial class InputHook
    {
        internal delegate bool MouseEvHandler(MOUSEDATA e, int dx, int dy);

        internal delegate void KeybdEvHandler(KEYBDDATA e);

        [StructLayout(LayoutKind.Sequential)]
        private struct MouseHookStruct
        {
            internal NativeMethods.POINT Pt;
            internal int Hwnd;
            internal int WHitTestCode;
            internal int DwExtraInfo;
        }

        // http://msdn.microsoft.com/en-us/library/ms644970(VS.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        private struct MouseLLHookStruct
        {
            internal NativeMethods.POINT Pt;
            internal int MouseData;
            internal int Flags;
            internal int Time;
            internal IntPtr DwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KeyboardHookStruct
        {
            internal int VkCode;
            internal int ScanCode;
            internal int Flags;
            internal int Time;
            internal IntPtr DwExtraInfo;
        }

        internal event MouseEvHandler MouseEvent;

        internal event KeybdEvHandler KeyboardEvent;

        private int hMouseHook;
        private int hKeyboardHook;
        private byte localModifiers;
        private HashSet<int> livePhysicalKeys = new();
        private PrivilegedCaptureSession captureSession;
        private volatile bool privilegedCaptureActive;
        internal bool IsCaptureInstalled => privilegedCaptureActive || (hMouseHook != 0 && hKeyboardHook != 0);
        private bool IsLiveCaptureActive => privilegedCaptureActive || hKeyboardHook != 0 || hMouseHook != 0;
        // Chromium's documented CRD0 tag distinguishes remote input from local
        // accessibility/remapping injectors. The injected flag is required too.
        private static readonly IntPtr ChromeRemoteInputTag = new(0x43524430);
        private (System.Drawing.Point Position, System.Drawing.Point RoutingAnchor)? remotePointerBaseline;
        private bool emergencyBackspaceDown;
        private static NativeMethods.HookProc mouseHookProcedure;
        private static NativeMethods.HookProc keyboardHookProcedure;

        private static MouseLLHookStruct mouseHookStruct;
        private static KeyboardHookStruct keyboardHookStruct;
        private static MOUSEDATA hookCallbackMouseData;
        private static KEYBDDATA hookCallbackKeybdData;

        private static bool altDown;

        internal static bool CtrlDown { get; private set; }

        private static readonly HeldKeyChord easyMouseKeys = new();
        private static volatile bool recordingKeys;
        internal static volatile Action<int, bool> KeyRecorder;
        internal static bool RecordingKeys
        {
            get => recordingKeys;
            set => Common.DoSomethingInTheInputCallbackThread(() =>
            {
                if (value)
                {
                    // Finish remote DOWNs before recording stops forwarding input to that PC.
                    foreach (int key in easyMouseKeys.DownKeys)
                    {
                        var release = new KEYBDDATA { wVk = (short)key, dwFlags = (int)WM.LLKHF.UP };
                        Common.Hook?.KeyboardEvent?.Invoke(release);
                    }
                    easyMouseKeys.Clear();
                    Event.SetMouseSwitchActivation(false);
                    Common.Hook?.ResetLastSwitchKeys();
                }
                recordingKeys = value;
            });
        }

        internal static bool EasyMouseKeyDown => easyMouseKeys.IsActive(
            (EasyMouseOption)Setting.Values.EasyMouse, Setting.Values.EasyMouseActivationKeys);

        internal InputHook()
        {
            Start();
        }

        ~InputHook()
        {
            Stop();
        }

        internal void Start(bool showError = true)
        {
            Stop();
            remotePointerBaseline = null;
            int le;
            bool er = false;
            var initialPosition = new System.Drawing.Point();
            NativeMethods.GetCursorPos(ref initialPosition);
            Common.LastPos = initialPosition;
            Event.ResetMonitorPointer(initialPosition);

            if (TryStartPrivilegedCapture())
            {
                SeedHeldPhysicalKeys();
                Common.InitLastInputEventCount();
                Logger.Log("Privileged SYSTEM input capture connected.");
                return;
            }

            // Install Mouse Hook
            mouseHookProcedure = new NativeMethods.HookProc(MouseHookProc);
            hMouseHook = NativeMethods.SetWindowsHookEx(
                WM.WH_MOUSE_LL,
                mouseHookProcedure,
#if PORTABLE_SINGLE_FILE
                NativeMethods.GetModuleHandle(null),
#else
                Marshal.GetHINSTANCE(
                    Assembly.GetExecutingAssembly().GetModules()[0]),
#endif
                0);

            if (hMouseHook == 0)
            {
                le = Marshal.GetLastWin32Error();
                Logger.Log("Error installing Mouse hook: " + le.ToString(CultureInfo.CurrentCulture));
                er = true;
                Stop();
            }

            // Install Keyboard Hook
            keyboardHookProcedure = new NativeMethods.HookProc(KeyboardHookProc);
            hKeyboardHook = NativeMethods.SetWindowsHookEx(
                WM.WH_KEYBOARD_LL,
                keyboardHookProcedure,
#if PORTABLE_SINGLE_FILE
                NativeMethods.GetModuleHandle(null),
#else
                Marshal.GetHINSTANCE(
                    Assembly.GetExecutingAssembly().GetModules()[0]),
#endif
                0);
            if (hKeyboardHook == 0)
            {
                le = Marshal.GetLastWin32Error();
                Logger.Log("Error installing keyboard hook: " + le.ToString(CultureInfo.CurrentCulture));
                er = true;
                Stop();
            }

            if (er)
            {
                if (showError && !Common.RunOnLogonDesktop && !Common.RunOnScrSaverDesktop)
                {
                    _ = MessageBox.Show(
                        "Error installing keyboard/Mouse hook!",
                        Application.ProductName,
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
            }
            else
            {
                // Seed native holds after installation, before returning to the hook message loop.
                SeedHeldPhysicalKeys();
                Common.InitLastInputEventCount();
            }
        }

        private void SeedHeldPhysicalKeys()
        {
            localModifiers = 0;
            CtrlDown = altDown = false;
            (livePhysicalKeys ??= new()).Clear();
            easyMouseKeys.Clear();
            var candidates = new HashSet<int>
            {
                (int)VK.LSHIFT, (int)VK.RSHIFT, (int)VK.LCONTROL, (int)VK.RCONTROL,
                (int)VK.LMENU, (int)VK.RMENU, (int)VK.LWIN, (int)VK.RWIN,
            };
            if (Setting.Values?.EasyMouseActivationKeys != null)
                foreach (int key in Setting.Values.EasyMouseActivationKeys)
                    if (key is >= 1 and <= 255) candidates.Add(key);
            foreach (int key in candidates)
            {
                if ((NativeMethods.GetAsyncKeyState((IntPtr)key) & 0x8000) == 0) continue;
                livePhysicalKeys.Add(key);
                localModifiers |= ModifierBit(key);
                _ = easyMouseKeys.Update(key, true);
                if ((VK)key is VK.LCONTROL or VK.RCONTROL) CtrlDown = true;
                if ((VK)key is VK.LMENU or VK.RMENU) altDown = true;
            }
            Event.SetMouseSwitchActivation(EasyMouseKeyDown);
        }

        private void UnhookLocalHooks()
        {
            if (hMouseHook != 0)
            {
                int retMouse = NativeMethods.UnhookWindowsHookEx(hMouseHook);
                hMouseHook = 0;
                if (retMouse == 0)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Logger.Log("Exception uninstalling Mouse hook, error code: " + errorCode.ToString(CultureInfo.CurrentCulture));
                }
            }

            if (hKeyboardHook != 0)
            {
                int retKeyboard = NativeMethods.UnhookWindowsHookEx(hKeyboardHook);
                hKeyboardHook = 0;
                if (retKeyboard == 0)
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Logger.Log("Exception uninstalling keyboard hook, error code: " + errorCode.ToString(CultureInfo.CurrentCulture));
                }
            }
        }

        private void StopPrivilegedCapture()
        {
            privilegedCaptureActive = false;
            var session = Interlocked.Exchange(ref captureSession, null);
            session?.Dispose();
        }

        private bool TryStartPrivilegedCapture()
        {
            var form = Common.InputCallbackForm;
            if (form == null || form.IsDisposed || !form.IsHandleCreated) return false;
            IntPtr callbackHandle = form.Handle;
            if (callbackHandle == IntPtr.Zero) return false;
            var pipe = PrivilegedInput.TryConnectCapture();
            if (pipe == null) return false;
            var session = new PrivilegedCaptureSession(this, pipe, callbackHandle);
            captureSession = session;
            privilegedCaptureActive = true;
            session.Start();
            return true;
        }

        internal void DrainPendingCaptureFrames() => Volatile.Read(ref captureSession)?.DrainPendingFrame();

        private bool DispatchCaptureFrame(PrivilegedInput.CaptureFrame frame) => frame.Kind == 0
            ? ProcessMouseHookData(frame.WParam, frame.First, frame.Second, frame.Third, frame.Fourth, new IntPtr(frame.ExtraInfo))
            : ProcessKeyboardHookData(frame.WParam, frame.First, frame.Second, frame.Third, frame.Fourth, new IntPtr(frame.ExtraInfo));

        private void HandlePrivilegedCaptureDisconnected(PrivilegedCaptureSession disconnected)
        {
            if (Interlocked.CompareExchange(ref captureSession, null, disconnected) != disconnected) return;
            privilegedCaptureActive = false;
            Common.InputCallbackForm?.NotifyPrivilegedCaptureLost();
        }

        internal void FallbackFromPrivilegedCapture()
        {
            if (privilegedCaptureActive || (hMouseHook != 0 && hKeyboardHook != 0)) return;
            Start(showError: false);
            Logger.Log("Privileged input capture unavailable; active local hooks resumed.");
        }

        internal void Stop()
        {
            StopPrivilegedCapture();
            livePhysicalKeys?.Clear();
            easyMouseKeys.Clear();
            Event.SetMouseSwitchActivation(false);
            UnhookLocalHooks();
        }

        // Better performance, compared to Marshal.PtrToStructure.
        private static MouseLLHookStruct LParamToMouseLLHookStruct(IntPtr lParam)
        {
            unsafe
            {
                return *(MouseLLHookStruct*)lParam;
            }
        }

        private static KeyboardHookStruct LParamToKeyboardHookStruct(IntPtr lParam)
        {
            unsafe
            {
                return *(KeyboardHookStruct*)lParam;
            }
        }

        private sealed class PrivilegedCaptureSession(InputHook owner, NamedPipeClientStream pipe, IntPtr callbackHandle) : IDisposable
        {
            private readonly object stateGate = new();
            private readonly CancellationTokenSource cancel = new();
            private readonly ManualResetEventSlim frameDone = new(false);
            private readonly byte[] readBuffer = new byte[PrivilegedInput.CaptureFrameSize];
            private readonly byte[] writeBuffer = new byte[1];
            private PrivilegedInput.CaptureFrame pendingFrame;
            private bool hasPendingFrame;
            private bool frameCompleted;
            private bool pendingSuppress;
            private bool stopRequested;
            private bool disposed;
            private System.Threading.Thread readerThread;

            internal void Start()
            {
                readerThread = new System.Threading.Thread(ReaderLoop)
                {
                    IsBackground = true,
                    Name = "MWBP-PrivilegedCaptureClient",
                };
                readerThread.Start();
            }

            internal void DrainPendingFrame()
            {
                PrivilegedInput.CaptureFrame frame;
                lock (stateGate)
                {
                    if (stopRequested || disposed || !hasPendingFrame) return;
                    frame = pendingFrame;
                    hasPendingFrame = false;
                }
                bool suppress = false;
                try { suppress = owner.DispatchCaptureFrame(frame); }
                finally
                {
                    lock (stateGate)
                    {
                        if (!disposed)
                        {
                            pendingSuppress = suppress;
                            frameCompleted = true;
                            frameDone.Set();
                        }
                    }
                }
            }

            private void ReaderLoop()
            {
                try
                {
                    while (!stopRequested && !cancel.IsCancellationRequested)
                    {
                        pipe.ReadExactlyAsync(readBuffer.AsMemory(0, PrivilegedInput.CaptureFrameSize), cancel.Token)
                            .AsTask().GetAwaiter().GetResult();
                        var frame = PrivilegedInput.ReadCaptureFrame(readBuffer);
                        lock (stateGate)
                        {
                            if (stopRequested || disposed) break;
                            pendingFrame = frame;
                            hasPendingFrame = true;
                            frameCompleted = false;
                            pendingSuppress = false;
                            frameDone.Reset();
                        }
                        if (!NativeMethods.PostMessage(callbackHandle, FrmInputCallback.CaptureDispatchMessage, IntPtr.Zero, IntPtr.Zero))
                            break;
                        if (!frameDone.Wait(90, cancel.Token))
                            break;
                        lock (stateGate)
                        {
                            if (stopRequested || disposed || !frameCompleted) break;
                            writeBuffer[0] = (byte)(pendingSuppress ? 1 : 0);
                        }
                        pipe.WriteAsync(writeBuffer, 0, 1, cancel.Token).GetAwaiter().GetResult();
                    }
                }
                catch (Exception error) when (error is IOException or EndOfStreamException or ObjectDisposedException or OperationCanceledException)
                {
                }
                finally
                {
                    pipe.Dispose();
                    if (!stopRequested) owner.HandlePrivilegedCaptureDisconnected(this);
                }
            }

            public void Dispose()
            {
                lock (stateGate)
                {
                    if (disposed) return;
                    stopRequested = true;
                    hasPendingFrame = false;
                    frameCompleted = false;
                    frameDone.Set();
                }
                try { cancel.Cancel(); } catch (ObjectDisposedException) { }
                pipe.Dispose();
                if (readerThread != null && System.Threading.Thread.CurrentThread != readerThread)
                    readerThread.Join(500);
                lock (stateGate)
                {
                    disposed = true;
                    frameDone.Dispose();
                    cancel.Dispose();
                }
            }
        }

        private void ReconcileLivePhysicalKeys(int activeDownVk = -1) =>
            ReconcileHeldKeys(vk => (NativeMethods.GetAsyncKeyState((IntPtr)vk) & 0x8000) != 0, activeDownVk);

        internal void ReconcileHeldKeys(Func<int, bool> isKeyPhysicallyDown, int activeDownVk = -1)
        {
            var tracked = livePhysicalKeys != null && livePhysicalKeys.Count != 0
                ? new List<int>(livePhysicalKeys)
                : !IsLiveCaptureActive ? new List<int>(easyMouseKeys.DownKeys) : null;
            if (tracked == null || tracked.Count == 0) return;
            bool wasActive = EasyMouseKeyDown;
            bool removedControl = false;
            bool removedAlt = false;
            foreach (int vk in tracked)
            {
                if (vk == activeDownVk || isKeyPhysicallyDown(vk)) continue;
                livePhysicalKeys?.Remove(vk);
                _ = easyMouseKeys.Update(vk, false);
                localModifiers = (byte)(localModifiers & ~ModifierBit(vk));
                if ((VK)vk is VK.LCONTROL or VK.RCONTROL) removedControl = true;
                if ((VK)vk is VK.LMENU or VK.RMENU) removedAlt = true;
            }
            if (removedControl) CtrlDown = easyMouseKeys.IsActive(EasyMouseOption.Ctrl, Array.Empty<int>());
            if (removedAlt) altDown = easyMouseKeys.IsActive(EasyMouseOption.Alt, Array.Empty<int>());
            bool active = EasyMouseKeyDown;
            if (wasActive != active) Event.SetMouseSwitchActivation(active);
        }

        private int MouseHookProc(int nCode, int wParam, IntPtr lParam)
        {
            if (nCode < 0) return NativeMethods.CallNextHookEx(hMouseHook, nCode, wParam, lParam);
            mouseHookStruct = LParamToMouseLLHookStruct(lParam);
            return ProcessMouseHookData(wParam, mouseHookStruct.Pt.x, mouseHookStruct.Pt.y, mouseHookStruct.MouseData, mouseHookStruct.Flags, mouseHookStruct.DwExtraInfo)
                ? 1
                : NativeMethods.CallNextHookEx(hMouseHook, nCode, wParam, lParam);
        }

        internal bool ProcessMouseHookData(int wParam, int x, int y, int mouseData, int flags, IntPtr dwExtraInfo)
        {
            using var dispatch = new InputHookDispatch(true);
            mouseHookSeenAt = Environment.TickCount64;
            Event.InputEventCount++;
            if ((flags & 1) != 0 && dwExtraInfo == ChromeRemoteInputTag)
            {
                if (wParam == WM.WM_MOUSEMOVE)
                    remotePointerBaseline = (new(x, y), Common.LastPos);
                return false;
            }
            if ((flags & 1) != 0 && dwExtraInfo == InputSimulation.InjectedInputTag)
            {
                if (wParam == WM.WM_MOUSEMOVE && remotePointerBaseline.HasValue)
                    remotePointerBaseline = (new(x, y), Common.LastPos);
                if (wParam == WM.WM_MOUSEMOVE && Common.DesMachineID == Common.MachineID)
                    Event.ResetMonitorPointer(new System.Drawing.Point(x, y));
                return false;
            }
            Event.RealInputEventCount++;
            try
            {
                if (IsLiveCaptureActive && (flags & 1) == 0 && livePhysicalKeys != null && livePhysicalKeys.Count > 0)
                    ReconcileLivePhysicalKeys();
                if (wParam == WM.WM_MOUSEMOVE && remotePointerBaseline is { } baseline)
                {
                    // CRD can warp the OS pointer while the physical pointer's
                    // logical monitor stays on a peer. Do not turn that warp into dx/dy.
                    if (Common.LastPos == baseline.RoutingAnchor) Common.LastPos = baseline.Position;
                    remotePointerBaseline = null;
                }
                if (DragDrop.HandleCancelMouse(wParam)) return true;
                hookCallbackMouseData = new MOUSEDATA
                {
                    X = x, Y = y, dwFlags = wParam,
                    WheelDelta = (short)((mouseData >> 16) & 0xffff),
                };
                bool suppress = MouseEvent?.Invoke(hookCallbackMouseData,
                    x - Common.LastPos.X, y - Common.LastPos.Y) ?? false;
                DragDrop.DragDropStep01(wParam);
                DragDrop.DragDropStep09(wParam);
                return suppress;
            }
            catch (Exception e)
            {
                Logger.Log(e);
                return false;
            }
        }

        private int KeyboardHookProc(int nCode, int wParam, IntPtr lParam)
        {
            if (nCode < 0) return NativeMethods.CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
            keyboardHookStruct = LParamToKeyboardHookStruct(lParam);
            return ProcessKeyboardHookData(wParam, keyboardHookStruct.VkCode, keyboardHookStruct.ScanCode, keyboardHookStruct.Flags, keyboardHookStruct.Time, keyboardHookStruct.DwExtraInfo)
                ? 1
                : NativeMethods.CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
        }

        internal bool ProcessKeyboardHookData(int wParam, int vkCode, int scanCode, int flags, int time, IntPtr dwExtraInfo)
        {
            using var dispatch = new InputHookDispatch(true);
            keyboardHookSeenAt = Environment.TickCount64;
            byte modifier = ModifierBit(vkCode);
            bool up = (flags & (int)WM.LLKHF.UP) != 0;
            Event.InputEventCount++;
            if ((flags & 0x10) != 0 && dwExtraInfo == ChromeRemoteInputTag)
                return false;
            if (RecordingKeys)
            {
                easyMouseKeys.Update(vkCode, !up);
                var recorder = KeyRecorder;
                if (recorder != null)
                {
                    recorder(vkCode, !up);
                    if (!up) return true;
                }
                // UP also finishes any Windows DOWN that preceded the recording dialog.
                return PassKeyboardEvent(modifier, up);
            }

            if ((flags & 0x10) != 0 && dwExtraInfo == InputSimulation.InjectedInputTag)
                return PassKeyboardEvent(modifier, up);

            Event.RealInputEventCount++;
            if (IsLiveCaptureActive && (flags & 0x10) == 0)
            {
                ReconcileLivePhysicalKeys(activeDownVk: !up ? vkCode : -1);
                if (!up) (livePhysicalKeys ??= new()).Add(vkCode);
                else livePhysicalKeys?.Remove(vkCode);
            }

            bool physicalBackspace = (VK)vkCode == VK.BACK && (flags & 0x10) == 0;
            if (physicalBackspace && emergencyBackspaceDown)
            {
                if (up) emergencyBackspaceDown = false;
                return true;
            }

            // Reserved escape: extra stale keys and the configurable shortcut switch
            // must never prevent the physical controller from taking its PC back.
            if (!up && physicalBackspace
                && easyMouseKeys.IsActive(EasyMouseOption.Ctrl, Array.Empty<int>())
                && easyMouseKeys.IsActive(EasyMouseOption.Alt, Array.Empty<int>()))
            {
                RestoreLocalControl();
                emergencyBackspaceDown = true;
                Common.InputCallbackForm?.CheckInputHealth(force: true);
                Logger.Log("Emergency keyboard return: restored local control.");
                return true;
            }

            hookCallbackKeybdData.dwFlags = flags;
            hookCallbackKeybdData.wVk = (short)vkCode;

            if (KeyboardEvent != null)
            {
                if (!ProcessKeyEx(vkCode, flags, hookCallbackKeybdData))
                {
                    return true;
                }

                KeyboardEvent(hookCallbackKeybdData);

            }

            if (Common.DesMachineID == ID.NONE || Common.DesMachineID == ID.ALL || Common.DesMachineID == Common.MachineID
                || up && (localModifiers & modifier) != 0)
            {
                return PassKeyboardEvent(modifier, up);
            }
            else
            {
                return true;
            }
        }

        private void RestoreLocalControl()
        {
            remotePointerBaseline = null;
            var previous = Common.DesMachineID;
            var transport = Common.Sk;
            var point = Common.LastPos;
            NativeMethods.GetCursorPos(ref point);
            Event.ReturnToLocalControl(point);
            livePhysicalKeys?.Clear();
            easyMouseKeys.Clear();
            ResetLastSwitchKeys();
            transport?.ReleaseInput(previous);
        }

        private bool PassKeyboardEvent(byte modifier, bool up)
        {
            localModifiers = up ? (byte)(localModifiers & ~modifier) : (byte)(localModifiers | modifier);
            return false;
        }

        private static byte ModifierBit(int key) => (VK)key switch
        {
            VK.SHIFT or VK.LSHIFT => 1,
            VK.RSHIFT => 2,
            VK.CONTROL or VK.LCONTROL => 4,
            VK.RCONTROL => 8,
            VK.MENU or VK.LMENU => 16,
            VK.RMENU => 32,
            VK.LWIN => 64,
            VK.RWIN => 128,
            _ => 0,
        };

        private bool ProcessKeyEx(int vkCode, int flags, KEYBDDATA hookCallbackKeybdData)
        {
            bool wasActive = EasyMouseKeyDown;
            bool firstPress = easyMouseKeys.Update(vkCode, (flags & (int)WM.LLKHF.UP) == 0);
            bool active = EasyMouseKeyDown;
            if (wasActive != active) Event.SetMouseSwitchActivation(active);
            if ((flags & (int)WM.LLKHF.UP) == (int)WM.LLKHF.UP)
            {
                switch ((VK)vkCode)
                {
                    case VK.LCONTROL:
                    case VK.RCONTROL:
                        CtrlDown = false;
                        break;

                    case VK.LMENU:
                    case VK.RMENU:
                        altDown = false;
                        break;

                    default:
                        break;
                }
            }
            else
            {
                switch ((VK)vkCode)
                {
                    case VK.LCONTROL:
                    case VK.RCONTROL:
                        CtrlDown = true;
                        break;

                    case VK.LMENU:
                    case VK.RMENU:
                        altDown = true;
                        break;

                    case VK.DELETE:
                        if (CtrlDown && altDown)
                        {
                            CtrlDown = altDown = false;
                            KeyboardEvent(hookCallbackKeybdData);

                            if (Common.DesMachineID != ID.ALL)
                            {
                                MachineStuff.SwitchToMachine(Common.MachineName.Trim());
                            }

                            /*
#if CUSTOMIZE_LOGON_SCREEN
                           Common.DoSomethingInUIThread(delegate()
                           {
                               Common.MainForm.LoadNewLogonBackground();
                           });
#endif
* */
                        }

                        break;

                    case VK.ESCAPE:
                        if (Common.IsTopMostMessageNotNull())
                        {
                            Common.HideTopMostMessage();
                        }

                        break;

                    default:
                        break;
                }
                return ProcessHotKeys(firstPress);
            }

            return true;
        }

        private static long lastHotKeyLockMachine;

        private bool ProcessHotKeys(bool firstPress)
        {
            if (RecordingKeys || !Setting.Values.KeyboardShortcutsEnabled) return true;
            KeyboardAction? match = null;
            foreach (var action in Enum.GetValues<KeyboardAction>())
                if (easyMouseKeys.MatchesExact(Setting.Values.GetShortcutKeys(action))) { match = action; break; }
            if (match == null) return true;
            if (!firstPress) return false; // Consume auto-repeat without cycling through PCs again.
            if (match <= KeyboardAction.Computer4) return !Switch2((int)match.Value);
            if (match == KeyboardAction.NextComputer)
            {
                string name = MachineStuff.NextMachineName();
                if (name != null) MachineStuff.SwitchToMachine(name);
            }
            else if (match == KeyboardAction.AllComputers)
            {
                ResetLastSwitchKeys();
                MachineStuff.SwitchToMultipleMode(Common.DesMachineID != ID.ALL, true);
            }
            else if (match == KeyboardAction.ToggleEdgeSwitching)
            {
                if (!Common.RunOnLogonDesktop && !Common.RunOnScrSaverDesktop)
                {
                    var option = (EasyMouseOption)Setting.Values.EasyMouse;
                    if (option is EasyMouseOption.Disable or EasyMouseOption.Enable)
                    {
                        Setting.Values.EasyMouse = (int)(option == EasyMouseOption.Disable ? EasyMouseOption.Enable : EasyMouseOption.Disable);
                        Setting.Values.CommitSharedSettings();
                        MachineStuff.SendMachineMatrix();
                    }
                }
            }
            else if (match == KeyboardAction.Reconnect)
            {
                Common.ShowToolTip("Reconnecting...", 2000);
                Common.LastReconnectByHotKeyTime = Common.GetTick();
                InitAndCleanup.PleaseReopenSocket = InitAndCleanup.REOPEN_WHEN_HOTKEY;
            }
            else if (match == KeyboardAction.LockComputers && !Common.RunOnLogonDesktop && !Common.RunOnScrSaverDesktop)
            {
                bool all = Common.GetTick() - lastHotKeyLockMachine < 500;
                if (all) MachineStuff.SwitchToMultipleMode(true, true);
                // Send the Windows lock command, independently of each peer's shortcut assignment.
                foreach (short key in new short[] { (short)VK.LWIN, (short)'L' })
                    KeyboardEvent(new KEYBDDATA { wVk = key });
                foreach (short key in new short[] { (short)'L', (short)VK.LWIN })
                    KeyboardEvent(new KEYBDDATA { wVk = key, dwFlags = (int)WM.LLKHF.UP });
                if (all)
                {
                    MachineStuff.SwitchToMultipleMode(false, true);
                    _ = NativeMethods.LockWorkStation();
                }
                lastHotKeyLockMachine = Common.GetTick();
            }
            return false;
        }
        private static bool Switch2(int index)
        {
            if (MachineStuff.MachineMatrix != null && MachineStuff.MachineMatrix.Length > index)
            {
                string mcName = MachineStuff.MachineMatrix[index].Trim();
                if (!string.IsNullOrEmpty(mcName))
                {
                    MachineStuff.SwitchToMachine(mcName);

                    if (!Common.RunOnLogonDesktop && !Common.RunOnScrSaverDesktop)
                    {
                        Common.ShowToolTip(Ui.Format("Control switched to {0}.", mcName), 3000);
                    }

                    return true;
                }
            }

            return false;
        }

        internal void ResetLastSwitchKeys()
        {
            CtrlDown = altDown = false;
        }
    }
}
