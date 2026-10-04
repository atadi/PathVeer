using System.Threading;
using PathVeer.Core;
using PathVeer.Core.Configuration;
using PathVeer.Core.CustomRoutes;
using PathVeer.Core.Networking;
using PathVeer.Core.Prefixes;
using PathVeer.Core.Routing;
using PathVeer.Core.Runtime;
using PathVeer.Core.Runtime.Execution;
using PathVeer.Core.Runtime.Profiling;
using PathVeer.Core.Runtime.Reconciliation;
using PathVeer.Core.State;
using PathVeer.Core.Vpn;
using PathVeer.Service;
using PathVeer.Service.Ipc;
using PathVeer.Service.Operations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace PathVeer.Service.Tests;

/// <summary>
/// Phase 34.4 startup gating: a missing or corrupt DesiredConfiguration must
/// never cause route mutation and must not crash the host. A valid
/// configuration reconciles normally (and, because the worker polls, a valid
/// configuration supplied after start is picked up without a restart).
/// </summary>
public sealed class IranDirectWorkerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _configPath;
    private readonly DesiredConfigurationStore _configStore;
    private readonly DesiredConfigurationService _configurationService;

    public IranDirectWorkerTests()
    {
        _tempDir = Path.Combine(
            Path.GetTempPath(), "IranDirect.WorkerTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _configPath = Path.Combine(_tempDir, "desired-configuration.json");
        _configStore = new DesiredConfigurationStore(
            _configPath, new DesiredConfigurationValidator());
        _configurationService = new DesiredConfigurationService(_configStore);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { }
    }

    [Fact]
    public async Task MissingConfiguration_DoesNotReconcile_AndDoesNotThrow()
    {
        // No config file exists.
        var harness = BuildHarness(out FakeExecutor executor);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        // ExecuteAsync must complete/abort cleanly on cancellation and never
        // invoke the executor (no route mutation).
        await RunUntilCanceled(harness.Worker, cts);

        Assert.Equal(0, executor.CallCount);
    }

    [Fact]
    public async Task CorruptConfiguration_DoesNotReconcile_AndDoesNotThrow()
    {
        File.WriteAllText(_configPath, "not valid json {{{");

        var harness = BuildHarness(out FakeExecutor executor);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        await RunUntilCanceled(harness.Worker, cts);

        Assert.Equal(0, executor.CallCount);
    }

    [Fact]
    public async Task CorruptState_StartupReconciliation_DoesNotInvokeExecutor()
    {
        await _configStore.SaveAsync(ConfigurationDefaults.Create() with
        {
            Enabled = true,
            VpnProfilePath = @"C:\VPN\work.ovpn"
        });

        var harness = BuildHarness(out FakeExecutor executor);
        await File.WriteAllBytesAsync(harness.StatePath, new byte[64]);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        await RunUntilCanceled(harness.Worker, cts);

        Assert.Equal(0, executor.CallCount);
        Assert.Equal(0, harness.RouteManager.MutationCallCount);
    }

    [Fact]
    public async Task ValidEnabledConfiguration_Reconciles()
    {
        await _configStore.SaveAsync(ConfigurationDefaults.Create() with
        {
            Enabled = true,
            VpnProfilePath = @"C:\VPN\work.ovpn"
        });

        var harness = BuildHarness(out FakeExecutor executor);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        await RunUntilCanceled(harness.Worker, cts);

        Assert.True(executor.CallCount >= 1,
            "A valid enabled configuration must drive at least one reconcile.");
    }

    [Fact]
    public async Task ValidDisabledConfiguration_DoesNotReconcile()
    {
        await _configStore.SaveAsync(ConfigurationDefaults.Create() with
        {
            Enabled = false,
            VpnProfilePath = @"C:\VPN\work.ovpn"
        });

        var harness = BuildHarness(out FakeExecutor executor);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        await RunUntilCanceled(harness.Worker, cts);

        Assert.Equal(0, executor.CallCount);
    }

    [Fact]
    public async Task NonIRDirectCountry_EnabledAndSupported_Reconciles()
    {
        // Phase 35.3 generalized the prefix source: a valid ISO country
        // (here IQ) is supported for routing through the same generic
        // pipeline. When a valid IQ dataset is available the worker must
        // reconcile (route mutation proceeds), not skip.
        await _configStore.SaveAsync(ConfigurationDefaults.Create() with
        {
            Enabled = true,
            VpnProfilePath = @"C:\VPN\work.ovpn",
            DirectCountryCode = DirectCountryCode.Parse("IQ")
        });

        var harness = BuildHarness(out FakeExecutor executor);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        await RunUntilCanceled(harness.Worker, cts);

        Assert.True(executor.CallCount >= 1,
            $"Expected IQ-enabled reconciliation to run; calls={executor.CallCount}");
    }

    // ---- harness construction (mirrors IranDirectControllerTests.TestContext) ----

    private Harness BuildHarness(out FakeExecutor executor)
    {
        executor = new FakeExecutor();

        string statePath = Path.Combine(_tempDir, "state.json");
        StateRepository stateRepository = new(statePath);
        RouteInventoryStore routeInventory = new(
            Path.Combine(_tempDir, "route-inventory.json"));
        VpnEndpointInventoryStore endpointInventory = new(
            Path.Combine(_tempDir, "endpoint-inventory.json"));

        CountryPrefixStore prefixStore = new(
            Path.Combine(_tempDir, "prefixes"));
        // Seed the selected country's last-known-good dataset so the worker
        // cycle can reconcile without hitting the network.
        IReadOnlyList<string> seed = ["203.0.113.0/24"];
        prefixStore.SavePrefixesAsync(
            DirectCountryCode.Parse("IQ"), seed).Wait();
        prefixStore.SavePrefixesAsync(
            DirectCountryCode.IR, seed).Wait();

        FakeRouteManager routeManager = new();
        GatewayDetector gatewayDetector = new();
        OpenVpnEndpointProvider vpnProvider = new(
            Path.Combine(_tempDir, "vpn-profile.ovpn"),
            new OpenVpnProfileParser(),
            new VpnEndpointResolver());
        VpnEndpointRouteManager vpnRouteManager = new(routeManager);

        FakeDecisionBuilder decisionBuilder = new();
        RuntimeCycleCoordinator coordinator = new(decisionBuilder);

        FakeCountryPrefixSource prefixSource = new(seed);

        PathVeerController controller = new(
            prefixSource,
            prefixStore,
            gatewayDetector,
            routeManager,
            stateRepository,
            routeInventory,
            vpnProvider,
            vpnRouteManager,
            endpointInventory,
            coordinator,
            executor,
            _configurationService,
            new RuntimeOperationStatus(),
            RuntimeCycleProfiler.Noop);

        // Default decision so the controller's cycle does not NPE.
        decisionBuilder.Decision = BuildDecision(enabled: false);

        OperationCoordinator operations = new();

        RouteMutationRecovery recovery = new(
            routeManager,
            routeInventory,
            endpointInventory,
            NullRouteMutationJournal.Instance);

        NoopPipeServer pipeServer = new(controller, operations);

        PathVeerWorker worker = new(
            controller,
            pipeServer,
            operations,
            _configurationService,
            recovery,
            NullLogger<PathVeerWorker>.Instance);

        return new Harness(
            worker,
            pipeServer,
            controller,
            stateRepository,
            statePath,
            routeManager);
    }

    [Fact]
    public async Task Diagnostic_ControllerRunCycle_Directly()
    {
        await _configStore.SaveAsync(ConfigurationDefaults.Create() with
        {
            Enabled = true,
            VpnProfilePath = @"C:\VPN\work.ovpn"
        });

        var harness = BuildHarness(out FakeExecutor executor);
        try
        {
            RuntimeCycleExecutionResult result =
                await harness.Controller.RunCycleAsync(CancellationToken.None);
            Assert.True(executor.CallCount >= 1, $"calls={executor.CallCount}");
        }
        catch (Exception ex)
        {
            throw new Exception(
                $"RunCycleAsync threw: {ex.GetType().Name}: {ex.Message}", ex);
        }
    }

    private sealed class Harness
    {
        public PathVeerWorker Worker { get; }
        public NoopPipeServer PipeServer { get; }
        public PathVeerController Controller { get; }
        public StateRepository StateRepository { get; }
        public FakeRouteManager RouteManager { get; }
        public string StatePath { get; }

        public Harness(
            PathVeerWorker worker,
            NoopPipeServer pipeServer,
            PathVeerController controller,
            StateRepository stateRepository,
            string statePath,
            FakeRouteManager routeManager)
        {
            Worker = worker;
            PipeServer = pipeServer;
            Controller = controller;
            StateRepository = stateRepository;
            StatePath = statePath;
            RouteManager = routeManager;
        }
    }

    private static async Task RunUntilCanceled(
        PathVeerWorker worker, CancellationTokenSource cts)
    {
        // BackgroundService.StartAsync kicks off ExecuteAsync without awaiting
        // it. Let the synchronous startup cycle run, then cancel to stop the
        // poll loop, then await the worker task so any fault surfaces.
        Task startTask = worker.StartAsync(cts.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(150), CancellationToken.None);
        cts.Cancel();
        await startTask;
    }

    private static RuntimeDecision BuildDecision(bool enabled) =>
        RuntimeDecision.Create(
            new RuntimePlanSnapshot
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
                    VpnEndpoints = [],
                    Prefixes = ["203.0.113.0/24"],
                    Routes = [],
                    ObservedAt = DateTimeOffset.UtcNow
                },
                Desired = new DesiredRuntime
                {
                    Enabled = enabled,
                    Blockers = [],
                    EndpointRoutes = [],
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
            },
            RuntimeReconciliationResult.NoChanges(),
            new RuntimeExecutionPlan { Steps = [] },
            DateTimeOffset.UtcNow);

    // ---- fakes ----

    private sealed class FakeExecutor : IRuntimeExecutor
    {
        public int CallCount { get; private set; }

        public RuntimeExecutionResult Result { get; set; } =
            RuntimeExecutionResult.NoExecutionRequired();

        public RuntimeExecutionPlan? ExecutedPlan { get; private set; }

        public Task<RuntimeExecutionResult> ExecuteAsync(
            RuntimeExecutionPlan plan,
            IProgress<RuntimeExecutionProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            ExecutedPlan = plan;
            return Task.FromResult(Result);
        }
    }

    private sealed class FakeRouteManager : IRouteManager
    {
        public int MutationCallCount { get; private set; }

        public Task<IReadOnlyList<SystemRoute>> GetIpv4RoutesAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SystemRoute>>(Array.Empty<SystemRoute>());

        public Task AddRoutesAsync(
            IReadOnlyCollection<ManagedRoute> routes,
            CancellationToken cancellationToken = default)
        {
            MutationCallCount++;
            return Task.CompletedTask;
        }

        public Task DeleteRoutesAsync(
            IReadOnlyCollection<ManagedRoute> routes,
            CancellationToken cancellationToken = default)
        {
            MutationCallCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeDecisionBuilder : IRuntimeDecisionBuilder
    {
        public RuntimeDecision? Decision { get; set; }

        public Task<RuntimeDecision> BuildAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Decision!);
        }
    }

    private sealed class FakeCountryPrefixSource : ICountryPrefixSource
    {
        private readonly IReadOnlyList<string> _prefixes;

        public FakeCountryPrefixSource(IReadOnlyList<string> prefixes)
        {
            _prefixes = prefixes;
        }

        public PrefixSourceDescriptor GetDescriptor(
            DirectCountryCode country) =>
            new()
            {
                Id = $"fake-{country.Code}",
                DisplayName = $"Fake {country.Code} source",
                Format = "ipv4-prefix-list",
                ParserVersion = "1.0",
                Uri = $"https://example.test/{country.Code}"
            };

        public Task<PrefixSourceFetchResult> FetchAsync(
            DirectCountryCode country,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new PrefixSourceFetchResult
            {
                Source = GetDescriptor(country),
                Prefixes = _prefixes,
                ContentHash = "fake-hash",
                CountryCode = country
            });
    }

    private sealed class NoopPipeServer : NamedPipeCommandServer
    {
        public NoopPipeServer(
            PathVeerController controller,
            OperationCoordinator operations)
            : base(
                controller,
                operations,
                null!, // OpenVpnEndpointProvider
                null!, // PathVeerDiagnosticsService
                null!, // DesiredConfigurationService
                null!, // RuntimeCoordinator
                null!, // CustomRouteCommandHandler
                null!, // RuntimeSnapshotCommandHandler
                null!, // PrefixUpdateCheckCommandHandler
                null!, // DiagnosticCommandHandler
                null!, // ExecutionPreviewCommandHandler
                null!, // SupportBundleCommandHandler
                null!, // CloudCommandHandler
                NullLogger<NamedPipeCommandServer>.Instance)
        {
        }

        public override Task RunAsync(CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
