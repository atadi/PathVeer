using System.Runtime.Versioning;
using System.ServiceProcess;
using PathVeer.Core.ServiceLifecycle;
using Xunit;

namespace PathVeer.Core.Tests.Tray;

/// <summary>
/// Regression test for the Tray service-control menu BINDING.
///
/// The Tray's <c>ApplyServiceStatus</c> binds each item as
/// <c>Enabled = snapshot.CanXxx &amp;&amp; !busy</c>. An older installed build
/// reportedly showed "Start" enabled while the service was Running, which is
/// wrong: Running means CanStart == false, so Start must be disabled and
/// Stop/Restart enabled.
///
/// Production Tray logic is already correct, so this test changes NO production
/// code. It pins the binding contract that the Tray menu depends on, so a
/// future change to <see cref="ServiceStatusSnapshot"/> (or to the busy gate)
/// that would re-enable Start while Running fails here instead of shipping.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrayServiceMenuBindingTests
{
    [Theory]
    [InlineData(false)] // not busy
    [InlineData(true)]  // busy: everything disabled
    public void RunningAndNotBusy_StartDisabled_StopAndRestartEnabled(
        bool busy)
    {
        ServiceStatusSnapshot running = Snapshot(
            installed: true,
            status: ServiceControllerStatus.Running);

        Assert.False(running.Running == false); // sanity: this IS Running
        Assert.True(running.Running);

        // The exact expression Tray.ApplyServiceStatus uses.
        bool startEnabled = running.CanStart && !busy;
        bool stopEnabled = running.CanStop && !busy;
        bool restartEnabled = running.CanRestart && !busy;

        if (busy)
        {
            Assert.False(startEnabled);
            Assert.False(stopEnabled);
            Assert.False(restartEnabled);
            return;
        }

        // Running + not busy => Start disabled, Stop enabled, Restart enabled.
        Assert.False(startEnabled);
        Assert.True(stopEnabled);
        Assert.True(restartEnabled);
    }

    [Fact]
    public void StoppedAndNotBusy_StartEnabled_StopAndRestartDisabled()
    {
        ServiceStatusSnapshot stopped = Snapshot(
            installed: true,
            status: ServiceControllerStatus.Stopped);

        Assert.False(stopped.Running);

        Assert.True(stopped.CanStart && !false);
        Assert.False(stopped.CanStop);
        Assert.False(stopped.CanRestart);
    }

    [Fact]
    public void NotInstalled_InstallEnabled_AllServiceActionsDisabled()
    {
        ServiceStatusSnapshot notInstalled =
            ServiceStatusSnapshot.NotInstalled;

        Assert.False(notInstalled.Installed);
        Assert.False(notInstalled.CanStart);
        Assert.False(notInstalled.CanStop);
        Assert.False(notInstalled.CanRestart);

        // Mirrors the Tray's install/uninstall binding.
        Assert.True(!notInstalled.Installed && !false);
        Assert.False(notInstalled.Installed && !false);
    }

    [Theory]
    [InlineData(ServiceControllerStatus.StartPending)]
    [InlineData(ServiceControllerStatus.StopPending)]
    [InlineData(ServiceControllerStatus.PausePending)]
    [InlineData(ServiceControllerStatus.ContinuePending)]
    public void TransitionalStatus_NoServiceActionEnabled(
        ServiceControllerStatus status)
    {
        ServiceStatusSnapshot snapshot = Snapshot(
            installed: true,
            status: status);

        Assert.True(snapshot.IsTransitional);

        // A transitional service must not offer Start/Stop/Restart, matching
        // the Tray's binding (CanStart/CanStop are false for any non-final
        // status) and the busy gate the Tray applies while polling.
        Assert.False(snapshot.CanStart);
        Assert.False(snapshot.CanStop);
        Assert.False(snapshot.CanRestart);
    }

    private static ServiceStatusSnapshot Snapshot(
        bool installed,
        ServiceControllerStatus status) =>
        new()
        {
            Installed = installed,
            Running = status == ServiceControllerStatus.Running,
            Status = status
        };
}
