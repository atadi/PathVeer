namespace PathVeer.Core.Tests;

using System.Net;
using PathVeer.Core.Configuration;
using PathVeer.Core.Networking;
using PathVeer.Core.Persistence;
using PathVeer.Core.Prefixes;
using PathVeer.Core.Routing;
using PathVeer.Core.Runtime;
using PathVeer.Core.Runtime.Execution;
using PathVeer.Core.Runtime.Profiling;
using PathVeer.Core.Runtime.Reconciliation;
using PathVeer.Core.State;
using PathVeer.Core.Vpn;

public sealed class IranDirectControllerTests
{
    [Fact]
    public async Task Enable_CompletedExecution_UpdatesStateEnabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
        Assert.Null(state.LastError);
    }

    [Fact]
    public async Task Enable_NoExecutionRequired_UpdatesStateEnabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
    }

    [Fact]
    public async Task Enable_FailedExecution_DoesNotUpdateState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Failed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "test failure"
            }
        ], "test failure");

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.False(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
        Assert.Contains("1 step(s) failed.", state.LastError);
        Assert.Contains("Type:", state.LastError);
        Assert.Contains("Target:", state.LastError);
        Assert.Contains("test failure", state.LastError);
    }

    [Fact]
    public async Task Enable_CancelledExecution_DoesNotUpdateState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Cancelled([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Cancelled
            }
        ], "cancelled");

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.False(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
    }

    [Fact]
    public async Task Enable_PartiallyCompleted_DoesNotUpdateState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.PartiallyCompleted([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "first|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            },
            new RuntimeExecutionStepResult
            {
                StepIdentity = "second|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "partial failure"
            }
        ], "partial failure");

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.False(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
    }

    [Fact]
    public async Task Disable_CompletedExecution_UpdatesStateDisabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);

        RuntimeCycleExecutionResult result = await ctx.Controller.DisableAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
        Assert.Null(state.LastError);
    }

    [Fact]
    public async Task Disable_NoExecutionRequired_UpdatesStateDisabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();

        RuntimeCycleExecutionResult result = await ctx.Controller.DisableAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
    }

    [Fact]
    public async Task Disable_FailedExecution_DoesNotChangeState()
    {
        await using TestContext ctx = new();
        await ctx.StateRepository.SaveAsync(new PathVeerState
        {
            Enabled = true,
            Gateway = "192.168.1.1",
            InterfaceIndex = 10,
            InterfaceName = "Ethernet",
            PrefixCount = 1,
            EnabledAt = DateTimeOffset.UtcNow
        });
        ctx.ExecutorResult = RuntimeExecutionResult.Failed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "test failure"
            }
        ], "test failure");

        RuntimeCycleExecutionResult result = await ctx.Controller.DisableAsync();

        Assert.False(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
    }

    [Fact]
    public async Task Enable_DecisionAndExecutionPreservedInResult()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.NotNull(result.Decision);
        Assert.NotNull(result.Execution);
        Assert.Same(ctx.FakeExecutor.Result, result.Execution);
    }

    [Fact]
    public async Task Disable_DecisionAndExecutionPreservedInResult()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();

        RuntimeCycleExecutionResult result = await ctx.Controller.DisableAsync();

        Assert.NotNull(result.Decision);
        Assert.NotNull(result.Execution);
        Assert.Same(ctx.FakeExecutor.Result, result.Execution);
    }

    [Fact]
    public async Task Enable_DesiredDisabled_DoesNotEnableState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = false;

        RuntimeCycleExecutionResult result = await ctx.Controller.EnableAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state = await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
    }

    [Fact]
    public async Task Enable_ExecutesPlanFromDecision()
    {
        await using TestContext ctx = new();
        RuntimeExecutionStep expectedStep = new()
        {
            Kind = RuntimeExecutionStepKind.AddPrefixRoute,
            Identity = "203.0.113.0/24|192.168.1.1|10",
            DestinationPrefix = "203.0.113.0/24",
            Gateway = "192.168.1.1",
            InterfaceIndex = 10,
            Metric = 5,
            Description = "Test step"
        };
        RuntimeExecutionPlan plan = new() { Steps = [expectedStep] };
        ctx.DesiredEnabled = true;
        ctx.DecisionPlan = plan;
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = expectedStep.Identity,
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);

        await ctx.Controller.EnableAsync();

        RuntimeExecutionPlan? executedPlan = ctx.FakeExecutor.ExecutedPlan;
        Assert.NotNull(executedPlan);
        Assert.Same(plan, executedPlan);
    }

    [Fact]
    public async Task Disable_UsesSamePipeline()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();

        await ctx.Controller.DisableAsync();

        RuntimeExecutionPlan? executedPlan = ctx.FakeExecutor.ExecutedPlan;
        Assert.NotNull(executedPlan);
    }

    [Fact]
    public async Task Disable_MutatedInfrastructureTrue_ClearsRouteInventory()
    {
        await using TestContext ctx = new();

        RouteInventory initialInventory = new()
        {
            Routes =
            [
                new RouteInventoryItem
                {
                    DestinationPrefix = "203.0.113.0/24",
                    Gateway = "192.168.1.1",
                    InterfaceIndex = 10,
                    Metric = 5
                }
            ]
        };
        await ctx.RouteInventoryStore.SaveAsync(initialInventory);

        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = false;

        await ctx.Controller.DisableAsync();

        RouteInventory inventory = await ctx.RouteInventoryStore.LoadAsync();
        Assert.Empty(inventory.Routes);
    }

    [Fact]
    public async Task Enable_CancellationTokenReachesCoordinatorAndExecutor()
    {
        await using TestContext ctx = new();
        using CancellationTokenSource cts = new();
        CancellationToken token = cts.Token;
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ctx.Controller.EnableAsync(token));
    }

    [Fact]
    public async Task RunCycle_EnabledDesired_UpdatesStateEnabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result =
            await ctx.Controller.RunCycleAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
        Assert.Null(state.LastError);
    }

    [Fact]
    public async Task RunCycle_DisabledDesired_UpdatesStateDisabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult =
            RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = false;

        RuntimeCycleExecutionResult result =
            await ctx.Controller.RunCycleAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
    }

    [Fact]
    public async Task RunCycle_FailedExecution_SetsLastError()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Failed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "test failure"
            }
        ], "test failure");

        RuntimeCycleExecutionResult result =
            await ctx.Controller.RunCycleAsync();

        Assert.False(result.IsSuccess);
        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.False(state.Enabled);
        Assert.Contains("1 step(s) failed.", state.LastError);
        Assert.Contains("Type:", state.LastError);
        Assert.Contains("Target:", state.LastError);
        Assert.Contains("test failure", state.LastError);
    }

    [Fact]
    public async Task RunCycle_SuccessfulCycle_ClearsLastError()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;
        await ctx.StateRepository.SaveAsync(
            new PathVeerState
            {
                Enabled = true,
                LastError = "previous error"
            });

        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);

        await ctx.Controller.RunCycleAsync();

        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
        Assert.Null(state.LastError);
    }

    [Fact]
    public async Task RunCycle_FailedCycle_PreservesLastError()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;
        await ctx.StateRepository.SaveAsync(
            new PathVeerState
            {
                Enabled = true,
                LastError = "previous error"
            });

        ctx.ExecutorResult = RuntimeExecutionResult.Failed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "new error"
            }
        ], "new error");

        await ctx.Controller.RunCycleAsync();

        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
        Assert.Contains("1 step(s) failed.", state.LastError);
        Assert.Contains("Type:", state.LastError);
        Assert.Contains("Target:", state.LastError);
        Assert.Contains("new error", state.LastError);
    }

    [Fact]
    public async Task RunCycle_StaleGatewayReplaced()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;

        uint staleIndex = 5;
        await ctx.StateRepository.SaveAsync(
            new PathVeerState
            {
                Enabled = false,
                Gateway = "192.168.1.1",
                InterfaceIndex = staleIndex,
                InterfaceName = "OldInterface"
            });

        RuntimePlanSnapshot plan = new()
        {
            Configuration = new DesiredConfiguration
                { Enabled = true },
            Observed = new ObservedRuntime
            {
                VpnProfileExists = true,
                VpnProfileValid = true,
                DirectGateway = new ObservedDirectGateway
                {
                    Address = "10.0.0.1",
                    InterfaceIndex = 20,
                    InterfaceName = "Ethernet"
                },
                VpnEndpoints = [],
                Prefixes = ["203.0.113.0/24"],
                Routes = [],
                ObservedAt = DateTimeOffset.UtcNow
            },
            Desired = new DesiredRuntime
            {
                Enabled = true,
                Blockers = [],
                EndpointRoutes = [],
                PrefixRoutes = []
            },
            PlannedAt = DateTimeOffset.UtcNow
        };

        ctx.FakeDecisionBuilder.Decision =
            RuntimeDecision.Create(
                plan,
                RuntimeReconciliationResult.NoChanges(),
                new RuntimeExecutionPlan { Steps = [] },
                DateTimeOffset.UtcNow);

        ctx.ExecutorResult =
            RuntimeExecutionResult.NoExecutionRequired();

        await ctx.Controller.RunCycleAsync();

        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
        Assert.Equal(20u, state.InterfaceIndex);
        Assert.Equal("Ethernet", state.InterfaceName);
        Assert.Equal("10.0.0.1", state.Gateway);
    }

    [Fact]
    public async Task RunCycle_CancellationTokenPropagates()
    {
        await using TestContext ctx = new();
        using CancellationTokenSource cts = new();
        CancellationToken token = cts.Token;
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ctx.Controller.RunCycleAsync(token));
    }

    [Fact]
    public async Task
        RunCycle_EnabledDesired_NoExecutionRequired_UpdatesStateEnabled()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult =
            RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result =
            await ctx.Controller.RunCycleAsync();

        Assert.True(result.IsSuccess);
        PathVeerState state =
            await ctx.StateRepository.LoadAsync();
        Assert.True(state.Enabled);
    }

    [Fact]
    public async Task Enable_Completed_PreservesOperationState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        await ctx.Controller.EnableAsync();

        RuntimeOperationStatus op = ctx.OperationStatus;
        Assert.Equal(OperationState.Enabling, op.State);
        Assert.NotNull(op.CompletedAt);
    }

    [Fact]
    public async Task Enable_OperationReportsProgress()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        await ctx.Controller.EnableAsync();

        Assert.Equal(1, ctx.OperationStatus.SucceededSteps);
    }

    [Fact]
    public async Task Disable_Completed_PreservesOperationState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);

        await ctx.Controller.DisableAsync();

        Assert.Equal(OperationState.Disabling, ctx.OperationStatus.State);
        Assert.Equal(1, ctx.OperationStatus.SucceededSteps);
        Assert.NotNull(ctx.OperationStatus.CompletedAt);
    }

    [Fact]
    public async Task Enable_FailedExecution_SetsOperationFailed()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.Failed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "test failure"
            }
        ], "test failure");
        ctx.DesiredEnabled = true;

        await ctx.Controller.EnableAsync();

        Assert.Equal(OperationState.Failed, ctx.OperationStatus.State);
        Assert.NotNull(ctx.OperationStatus.ErrorMessage);
    }

    [Fact]
    public async Task RunCycle_Completed_PreservesOperationState()
    {
        await using TestContext ctx = new();
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = true;

        await ctx.Controller.RunCycleAsync();

        Assert.Equal(OperationState.Repairing, ctx.OperationStatus.State);
        Assert.NotNull(ctx.OperationStatus.CompletedAt);
    }

    [Fact]
    public async Task GetStatusAsync_IncludesDesiredEnabled()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;

        PathVeerStatus status = await ctx.Controller.GetStatusAsync();

        Assert.True(status.DesiredEnabled);
        Assert.NotNull(status.Operation);
    }

    [Fact]
    public async Task GetStatusAsync_ReturnsOperationSnapshot()
    {
        await using TestContext ctx = new();

        PathVeerStatus status = await ctx.Controller.GetStatusAsync();

        Assert.NotNull(status.Operation);
        Assert.IsType<RuntimeOperationSnapshot>(status.Operation);
        Assert.Equal(OperationState.Idle, status.Operation.State);
        Assert.False(status.Operation.IsCompleted);
    }

    [Fact]
    public async Task Enable_ProducesExactlyOneEnableReport()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result =
            await ctx.Controller.EnableAsync();

        Assert.True(result.IsSuccess);

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        Assert.Equal("enable", report.Trigger);
        Assert.Equal(
            CycleCompletionStatus.Completed,
            report.CompletionStatus);
        Assert.Single(
            Directory.GetFiles(
                temp.Path, RuntimePerfReportStore.FilePattern));
    }

    [Fact]
    public async Task Disable_ProducesExactlyOneDisableReport()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.RemovePrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result =
            await ctx.Controller.DisableAsync();

        Assert.True(result.IsSuccess);

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        Assert.Equal("disable", report.Trigger);
        Assert.Single(
            Directory.GetFiles(
                temp.Path, RuntimePerfReportStore.FilePattern));
    }

    [Fact]
    public async Task RunCycle_InsideActiveEnableScope_KeepsEnableTrigger()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = true;

        using (profiler.BeginCycle("enable"))
        {
            RuntimeCycleExecutionResult result =
                await ctx.Controller.RunCycleAsync();

            Assert.True(result.IsSuccess);
        }

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        Assert.Equal("enable", report.Trigger);
        Assert.Single(
            Directory.GetFiles(
                temp.Path, RuntimePerfReportStore.FilePattern));
    }

    [Fact]
    public async Task Enable_WhenExecutorThrows_StillWritesFailedReport()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.FakeExecutor.ThrowOnExecute =
            new InvalidOperationException(
                "Inventory persistence failed.");
        ctx.DesiredEnabled = true;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => ctx.Controller.EnableAsync());

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        Assert.Equal("enable", report.Trigger);
        Assert.Equal(
            CycleCompletionStatus.Failed,
            report.CompletionStatus);
        Assert.Contains(
            "Inventory persistence failed.",
            report.ErrorSummary);
        Assert.Single(
            Directory.GetFiles(
                temp.Path, RuntimePerfReportStore.FilePattern));
    }

    [Fact]
    public async Task Enable_PartiallyCompleted_StillWritesReport()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.PartiallyCompleted(
        [
            new RuntimeExecutionStepResult
            {
                StepIdentity = "ok|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            },
            new RuntimeExecutionStepResult
            {
                StepIdentity = "bad|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Failed,
                ErrorMessage = "route not created"
            }
        ]);
        ctx.DesiredEnabled = true;

        RuntimeCycleExecutionResult result =
            await ctx.Controller.EnableAsync();

        Assert.False(result.IsSuccess);

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        Assert.Equal("enable", report.Trigger);
        Assert.Equal(
            CycleCompletionStatus.PartiallyCompleted,
            report.CompletionStatus);
    }

    [Fact]
    public async Task Enable_Cancelled_StillWritesCancelledReport()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();
        ctx.DesiredEnabled = true;
        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ctx.Controller.EnableAsync(cts.Token));

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        Assert.Equal("enable", report.Trigger);
        Assert.Equal(
            CycleCompletionStatus.Cancelled,
            report.CompletionStatus);
    }

    [Fact]
    public async Task Enable_RecordsExecutionTotalWhenExecutorRuns()
    {
        using TempDirectory temp = new();
        RuntimePerfReportStore store = new(temp.Path);
        RuntimeCycleProfiler profiler = new(
            enabled: true,
            store);
        await using TestContext ctx = new(profiler);
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "test|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "test",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        ctx.DesiredEnabled = true;

        await ctx.Controller.EnableAsync();

        RuntimeCyclePerfReport? report = store.ReadLatest();

        Assert.NotNull(report);
        RuntimePerfCategorySummary total = Assert.Single(
            report.Categories,
            c => c.Category ==
                RuntimePerfCategory.ExecutionTotal);
        Assert.True(total.Count >= 1);
    }

    [Fact]
    public async Task RunCycle_UnrecoverableCorruptState_DoesNotInvokeExecutor()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;
        ctx.DecisionPlan = new RuntimeExecutionPlan
        {
            Steps =
            [
                new RuntimeExecutionStep
                {
                    Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                    Identity = "route|id",
                    DestinationPrefix = "203.0.113.0/24",
                    Gateway = "192.0.2.1",
                    InterfaceIndex = 10,
                    Metric = 5,
                    Description = "test"
                }
            ]
        };
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "route|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "203.0.113.0/24",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);
        await File.WriteAllBytesAsync(ctx.StatePath, new byte[64]);

        await Assert.ThrowsAsync<PersistenceCorruptException>(
            () => ctx.Controller.RunCycleAsync());

        Assert.Equal(0, ctx.FakeExecutor.CallCount);
        Assert.Equal(0, ctx.RouteManager.MutationCallCount);
    }

    [Fact]
    public async Task RunCycle_CorruptStateWithValidBackup_RecoversBeforeExecutor()
    {
        await using TestContext ctx = new();
        await ctx.StateRepository.SaveAsync(new PathVeerState
        {
            Gateway = "192.0.2.1"
        });
        await ctx.StateRepository.SaveAsync(new PathVeerState
        {
            Gateway = "192.0.2.2"
        });
        await File.WriteAllBytesAsync(ctx.StatePath, new byte[64]);

        ctx.DesiredEnabled = true;
        ctx.DecisionPlan = new RuntimeExecutionPlan
        {
            Steps =
            [
                new RuntimeExecutionStep
                {
                    Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                    Identity = "route|id",
                    DestinationPrefix = "203.0.113.0/24",
                    Gateway = "192.0.2.1",
                    InterfaceIndex = 10,
                    Metric = 5,
                    Description = "test"
                }
            ]
        };
        ctx.ExecutorResult = RuntimeExecutionResult.Completed([
            new RuntimeExecutionStepResult
            {
                StepIdentity = "route|id",
                Kind = RuntimeExecutionStepKind.AddPrefixRoute,
                DestinationPrefix = "203.0.113.0/24",
                Status = RuntimeExecutionStepStatus.Succeeded
            }
        ]);

        await ctx.Controller.RunCycleAsync();

        Assert.Equal(1, ctx.FakeExecutor.CallCount);
        Assert.True(File.Exists(ctx.StatePath + ".bak"));
    }

    [Fact]
    public async Task RunCycle_MissingState_RetainsDefaultSemanticsAndExecutes()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;
        ctx.ExecutorResult = RuntimeExecutionResult.NoExecutionRequired();

        Assert.False(File.Exists(ctx.StatePath));

        await ctx.Controller.RunCycleAsync();

        Assert.Equal(1, ctx.FakeExecutor.CallCount);
        Assert.True(File.Exists(ctx.StatePath));
    }

    [Fact]
    public async Task Enable_UnrecoverableCorruptState_DoesNotInvokeExecutor()
    {
        await using TestContext ctx = new();
        ctx.DesiredEnabled = true;
        await File.WriteAllBytesAsync(ctx.StatePath, new byte[64]);

        await Assert.ThrowsAsync<PersistenceCorruptException>(
            () => ctx.Controller.EnableAsync());

        Assert.Equal(0, ctx.FakeExecutor.CallCount);
        Assert.Equal(0, ctx.RouteManager.MutationCallCount);
    }

    internal sealed class FakeDecisionBuilder : IRuntimeDecisionBuilder
    {
        public RuntimeDecision? Decision { get; set; }

        public Task<RuntimeDecision> BuildAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Decision!);
        }
    }

    internal sealed class FakeExecutor : IRuntimeExecutor
    {
        public int CallCount { get; private set; }

        public RuntimeExecutionResult Result { get; set; } =
            RuntimeExecutionResult.NoExecutionRequired();

        public Exception? ThrowOnExecute { get; set; }

        public RuntimeExecutionPlan? ExecutedPlan { get; private set; }

        public Task<RuntimeExecutionResult> ExecuteAsync(
            RuntimeExecutionPlan plan,
            IProgress<RuntimeExecutionProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            ExecutedPlan = plan;

            if (ThrowOnExecute is not null)
                throw ThrowOnExecute;

            return Task.FromResult(Result);
        }
    }

    internal sealed class FakeRouteManager : IRouteManager
    {
        public int MutationCallCount { get; private set; }
        public HashSet<string> Present { get; set; } = [];

        public Task AddRoutesAsync(
            IReadOnlyCollection<ManagedRoute> routes,
            CancellationToken cancellationToken = default)
        {
            MutationCallCount++;
            foreach (ManagedRoute route in routes)
                Present.Add(route.Identity);
            return Task.CompletedTask;
        }

        public Task DeleteRoutesAsync(
            IReadOnlyCollection<ManagedRoute> routes,
            CancellationToken cancellationToken = default)
        {
            MutationCallCount++;
            foreach (ManagedRoute route in routes)
                Present.Remove(route.Identity);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<SystemRoute>> GetIpv4RoutesAsync(
            CancellationToken cancellationToken = default)
        {
            IReadOnlyList<SystemRoute> routes = Present
                .Select(id =>
                {
                    string[] parts = id.Split('|', 3);
                    return new SystemRoute
                    {
                        DestinationPrefix = parts[0],
                        NextHop = IPAddress.Parse(parts[1]),
                        InterfaceIndex = uint.Parse(parts[2])
                    };
                })
                .ToList();
            return Task.FromResult(routes);
        }
    }

    private sealed class TestContext : IAsyncDisposable
    {
        private readonly string _tempDir;
        private readonly DesiredConfigurationService _configurationService;

        public StateRepository StateRepository { get; }
        public RouteInventoryStore RouteInventoryStore { get; }
        public PathVeerController Controller { get; }
        public FakeExecutor FakeExecutor { get; }
        public FakeDecisionBuilder FakeDecisionBuilder { get; }
        public FakeRouteManager RouteManager { get; }
        public string StatePath => Path.Combine(_tempDir, "state.json");
        public RuntimeOperationStatus OperationStatus { get; }
        public RuntimeCycleProfiler Profiler { get; }
        public string? PerfDirectory { get; }

        public RuntimeExecutionResult ExecutorResult
        {
            get => FakeExecutor.Result;
            set => FakeExecutor.Result = value;
        }

        public bool DesiredEnabled
        {
            get => false;
            set
            {
                RuntimePlanSnapshot plan = CreatePlan(value);
                RuntimeReconciliationResult reconciliation =
                    RuntimeReconciliationResult.NoChanges();
                RuntimeExecutionPlan executionPlan = new() { Steps = [] };
                RuntimeDecision decision = RuntimeDecision.Create(
                    plan, reconciliation, executionPlan, DateTimeOffset.UtcNow);
                FakeDecisionBuilder.Decision = decision;
                _ = _configurationService.SetEnabledAsync(value, CancellationToken.None)
                    .GetAwaiter().GetResult();
            }
        }

        public RuntimeExecutionPlan DecisionPlan
        {
            set
            {
                RuntimePlanSnapshot plan = CreatePlan(true);
                RuntimeChange[] changes = value.Steps
                    .Select(step => new RuntimeChange
                    {
                        Kind = MapKind(step.Kind),
                        Identity = step.Identity,
                        DestinationPrefix = step.DestinationPrefix,
                        Gateway = step.Gateway,
                        InterfaceIndex = step.InterfaceIndex,
                        Metric = step.Metric,
                        Description = step.Description
                    })
                    .ToArray();
                RuntimeReconciliationResult reconciliation =
                    RuntimeReconciliationResult.Planned(
                        new RuntimeChangeSet { Changes = changes });
                RuntimeDecision decision = RuntimeDecision.Create(
                    plan, reconciliation, value, DateTimeOffset.UtcNow);
                FakeDecisionBuilder.Decision = decision;
            }
        }

        public TestContext(
            RuntimeCycleProfiler? profiler = null,
            string? perfDirectory = null)
        {
            _tempDir = Path.Combine(
                Path.GetTempPath(), $"IranDirectTest_{Guid.NewGuid()}");
            Directory.CreateDirectory(_tempDir);

            Profiler = profiler ?? RuntimeCycleProfiler.Noop;
            PerfDirectory = perfDirectory;

            StateRepository = new StateRepository(
                StatePath);
            RouteInventoryStore = new RouteInventoryStore(
                Path.Combine(_tempDir, "route-inventory.json"));
            VpnEndpointInventoryStore endpointInventory = new(
                Path.Combine(_tempDir, "endpoint-inventory.json"));

            CountryPrefixStore prefixStore = new(
                Path.Combine(_tempDir, "prefixes"));
            prefixStore.SavePrefixesAsync(
                DirectCountryCode.IR,
                ["203.0.113.0/24"]).Wait();

            DesiredConfigurationStore configStore = new(
                Path.Combine(_tempDir, "config.json"),
                new DesiredConfigurationValidator());
            _configurationService = new DesiredConfigurationService(configStore);

            FakeExecutor = new FakeExecutor();
            FakeDecisionBuilder = new FakeDecisionBuilder();
            RuntimeCycleCoordinator coordinator = new(FakeDecisionBuilder);
            OperationStatus = new RuntimeOperationStatus();

            FakeRouteManager routeManager = new();
            RouteManager = routeManager;
            GatewayDetector gatewayDetector = new();
            OpenVpnEndpointProvider vpnProvider = new(
                Path.Combine(_tempDir, "vpn-profile.ovpn"),
                new OpenVpnProfileParser(),
                new VpnEndpointResolver());
            VpnEndpointRouteManager vpnRouteManager = new(routeManager);

            Controller = new PathVeerController(
                null!, // ICountryPrefixSource - not called in these tests
                prefixStore,
                gatewayDetector,
                routeManager,
                StateRepository,
                RouteInventoryStore,
                vpnProvider,
                vpnRouteManager,
                endpointInventory,
                coordinator,
                FakeExecutor,
                _configurationService,
                OperationStatus,
                Profiler);

            // Set a default decision so first call doesn't NPE
            DesiredEnabled = false;
        }

        public async ValueTask DisposeAsync()
        {
            try { Directory.Delete(_tempDir, recursive: true); }
            catch { /* ok */ }
            await ValueTask.CompletedTask;
        }

        private static RuntimePlanSnapshot CreatePlan(bool enabled)
        {
            return new RuntimePlanSnapshot
            {
                Configuration = new DesiredConfiguration { Enabled = enabled },
                Observed = new ObservedRuntime
                {
                    VpnProfileExists = true,
                    VpnProfileValid = true,
                    DirectGateway = new ObservedDirectGateway
                    {
                        Address = "192.168.1.1",
                        InterfaceIndex = 10,
                        InterfaceName = "Ethernet"
                    },
                    VpnEndpoints =
                    [
                        new ObservedVpnEndpoint
                        {
                            Host = "vpn.example.com",
                            Address = "10.0.0.1",
                            Port = 1194,
                            Protocol = "udp"
                        }
                    ],
                    Prefixes = ["203.0.113.0/24"],
                    Routes = [],
                    ObservedAt = DateTimeOffset.UtcNow
                },
                Desired = new DesiredRuntime
                {
                    Enabled = enabled,
                    Blockers = [],
                    EndpointRoutes =
                    [
                        new DesiredEndpointRoute
                        {
                            Host = "vpn.example.com",
                            Address = "10.0.0.1",
                            Port = 1194,
                            Protocol = "udp",
                            DestinationPrefix = "10.0.0.1/32",
                            Gateway = "192.168.1.1",
                            InterfaceIndex = 10,
                            Metric = 1
                        }
                    ],
                    PrefixRoutes = enabled
                        ? [new DesiredPrefixRoute
                        {
                            DestinationPrefix = "203.0.113.0/24",
                            Gateway = "192.168.1.1",
                            InterfaceIndex = 10,
                            Metric = 5
                        }]
                        : []
                },
                PlannedAt = DateTimeOffset.UtcNow
            };
        }

        private static RuntimeChangeKind MapKind(
            RuntimeExecutionStepKind kind) => kind switch
        {
            RuntimeExecutionStepKind.AddEndpointRoute =>
                RuntimeChangeKind.AddEndpointRoute,
            RuntimeExecutionStepKind.RemoveEndpointRoute =>
                RuntimeChangeKind.RemoveEndpointRoute,
            RuntimeExecutionStepKind.AddPrefixRoute =>
                RuntimeChangeKind.AddPrefixRoute,
            RuntimeExecutionStepKind.RemovePrefixRoute =>
                RuntimeChangeKind.RemovePrefixRoute,
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
    }

    private sealed class TempDirectory : IDisposable
    {
        public string Path { get; } =
            System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"IranPerfControllerTest_{Guid.NewGuid()}");

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                    Directory.Delete(Path, recursive: true);
            }
            catch
            {
                // Best-effort cleanup.
            }
        }
    }
}
