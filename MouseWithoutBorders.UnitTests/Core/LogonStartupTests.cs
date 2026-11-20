using System.Xml.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MouseWithoutBorders.Core;

namespace MouseWithoutBorders.UnitTests.Core;

[TestClass]
public sealed class LogonStartupTests
{
    private const string OwnerSid = "S-1-5-21-1-2-3-1001";
    private const string OwnerName = @"Example\Owner";
    private const string InstalledImage = @"C:\Program Files\MouseWithoutBordersPlus\MouseWithoutBordersPlus.exe";

    [TestMethod]
    public void TaskUsesOnlyTheInstalledImageInTheSigningInAccount()
    {
        var task = LogonStartup.CreateTaskDefinition(OwnerSid, InstalledImage, true);
        XNamespace ns = task.Name.Namespace;
        XElement trigger = task.Element(ns + "Triggers")!.Element(ns + "LogonTrigger")!;
        XElement principal = task.Element(ns + "Principals")!.Element(ns + "Principal")!;
        XElement settings = task.Element(ns + "Settings")!;
        XElement action = task.Element(ns + "Actions")!.Element(ns + "Exec")!;

        Assert.IsTrue(LogonStartup.OwnsDefinition(task, OwnerSid, OwnerName, InstalledImage));
        Assert.AreEqual(OwnerSid, (string?)trigger.Element(ns + "UserId"));
        Assert.IsNull(trigger.Element(ns + "Delay"));
        Assert.AreEqual("InteractiveToken", (string?)principal.Element(ns + "LogonType"));
        Assert.AreEqual("LeastPrivilege", (string?)principal.Element(ns + "RunLevel"));
        Assert.AreEqual("IgnoreNew", (string?)settings.Element(ns + "MultipleInstancesPolicy"));
        Assert.AreEqual("PT0S", (string?)settings.Element(ns + "ExecutionTimeLimit"));
        Assert.IsFalse((bool)settings.Element(ns + "DisallowStartIfOnBatteries")!);
        Assert.IsFalse((bool)settings.Element(ns + "StopIfGoingOnBatteries")!);
        Assert.AreEqual(InstalledImage, (string?)action.Element(ns + "Command"));
    }

    [TestMethod]
    public void ExistingTaskIsOwnedOnlyWithTheSameAccountAndCommand()
    {
        var task = LogonStartup.CreateTaskDefinition(OwnerSid, InstalledImage, true);
        XNamespace ns = task.Name.Namespace;
        task.Element(ns + "Triggers")!.Element(ns + "LogonTrigger")!.SetElementValue(ns + "UserId", OwnerName);
        Assert.IsTrue(LogonStartup.OwnsDefinition(task, OwnerSid, OwnerName, InstalledImage));
        Assert.IsFalse(LogonStartup.OwnsDefinition(task, OwnerSid + "1", @"Example\Other", InstalledImage));
        Assert.IsFalse(LogonStartup.OwnsDefinition(task, OwnerSid, OwnerName, @"C:\Foreign\MouseWithoutBordersPlus.exe"));
        task.Element(ns + "Actions")!.Element(ns + "Exec")!.SetElementValue(ns + "Arguments", "--other");
        Assert.IsFalse(LogonStartup.OwnsDefinition(task, OwnerSid, OwnerName, InstalledImage));
    }

    [TestMethod]
    public void ADisabledTaskOrLogonTriggerReportsAutoStartOff()
    {
        var task = LogonStartup.CreateTaskDefinition(OwnerSid, InstalledImage, false);
        XNamespace ns = task.Name.Namespace;
        Assert.IsFalse(LogonStartup.IsTaskEnabled(task));
        task.Element(ns + "Settings")!.SetElementValue(ns + "Enabled", true);
        Assert.IsTrue(LogonStartup.IsTaskEnabled(task));
        task.Element(ns + "Triggers")!.Element(ns + "LogonTrigger")!.SetElementValue(ns + "Enabled", false);
        Assert.IsFalse(LogonStartup.IsTaskEnabled(task));
    }

    [TestMethod]
    public void LegacyApprovalPreservesExplicitDisabledAndLeavesUnknownStateUnresolved()
    {
        Assert.AreEqual(true, LogonStartup.ReadLegacyApproval(null!));
        Assert.AreEqual(true, LogonStartup.ReadLegacyApproval(new byte[12] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
        Assert.AreEqual(false, LogonStartup.ReadLegacyApproval(new byte[12] { 3, 0, 0, 0, 64, 93, 36, 31, 251, 244, 210, 1 }));
        Assert.IsNull(LogonStartup.ReadLegacyApproval(new byte[12]));
        Assert.IsNull(LogonStartup.ReadLegacyApproval(new byte[] { 2 }));
        Assert.IsNull(LogonStartup.ReadLegacyApproval(2));
    }
}
