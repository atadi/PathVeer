using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using PathVeer.Core;
using PathVeer.Core.Configuration;
using PathVeer.Core.Ipc;
using PathVeer.Core.Networking;
using PathVeer.Core.Observability.Telemetry;
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
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace PathVeer.Service.Tests;

/// <summary>
/// Regression tests for the named-pipe EXCEPTION BOUNDARY.
///
/// INCIDENT: a valid <see cref="PathVeerCommand.Status"/> request reached the
/// server; a corrupted durable <c>state.json</c> made
/// <c>PathVeerController.GetStatusAsync</c> throw. The server's single
/// try-block wrapped BOTH request deserialization and command dispatch, so the
/// request-parsing <c>catch (JsonException)</c> caught the DOWNSTREAM failure
/// and answered <c>INVALID_JSON</c> / "The request could not be parsed." plus a
/// misleading "Invalid named-pipe JSON request." event. That misdiagnosed
/// persistence corruption as malformed IPC input.
///
/// These tests drive the REAL server over a REAL named pipe with the REAL
/// controller, so the corrupted-store failure is reproduced end to end rather
/// than simulated behind a seam.
/// </summary>
public sealed class NamedPipeCommandServerExceptionBoundaryTests
    : IDisposable
{
    private readonly string _tempDir;
    private readonly string _statePath;
    private readonly string _pipeName;

    public NamedPipeCommandServerExceptionBoundaryTests()
    {
        _tempDir = Path.Combine(
            Path.GetTempPath(),
            "PathVeer.IpcBoundaryTests",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(_tempDir);

        _statePath = Path.Combine(_tempDir, "state.json");

        // An ISOLATED pipe name. The real control pipe is owned by the live
        // PathVeer service on this machine; binding a test client to it would
        // silently exercise the live service instead of the code under test.
        _pipeName = "PathVeer.Control.Test." + Guid.NewGuid().ToString("N");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best effort */ }
    }

    // ---------------------------------------------------------------------
    // 1. Malformed inbound JSON -> INVALID_JSON, and NO command is dispatched.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task
        MalformedInboundJson_ReturnsInvalidJson_AndNeverDispatches()
    {
        NamedPipeCommandServer server = BuildServer();

        ServiceResponse response = await RoundTripAsync(
            server,
            "this is not json {{{");

        Assert.Equal("INVALID_JSON", response.ErrorCode);
        Assert.Equal(
            "The request could not be parsed.",
            response.Message);
        Assert.False(response.Success);

        // Decisive: a malformed document never reaches dispatch, so the durable
        // store is never consulted and no recovery side effect runs.
        Assert.False(File.Exists(_statePath + ".quarantine"));
        Assert.False(File.Exists(_statePath + ".bak"));
    }

    // ---------------------------------------------------------------------
    // 2. A VALID request whose dispatch throws a downstream JsonException
    //    must NOT be reported as INVALID_JSON.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task
        ValidRequest_DownstreamJsonException_IsNotInvalidJson()
    {
        // A FailClosed store (RouteInventoryStore uses the public JsonStore
        // constructor, which does NOT wrap corruption) raises the RAW
        // JsonException from WITHIN the command handler — the exact incident
        // shape. StateRepository is BackupRollback and wraps corruption in
        // PersistenceCorruptException; that case is covered separately below.
        string inventoryPath =
            Path.Combine(_tempDir, "route-inventory.json");

        File.WriteAllText(inventoryPath, "{ this is not valid json :::: ");

        NamedPipeCommandServer server = BuildServer();

        ServiceResponse response = await RoundTripAsync(
            server,
            StatusRequestJson());

        Assert.NotEqual("INVALID_JSON", response.ErrorCode);
        Assert.False(response.Success);

        // The request WAS valid and WAS dispatched — only the downstream
        // execution failed. The buggy build answered INVALID_JSON here.
        Assert.Equal("COMMAND_FAILED", response.ErrorCode);
    }

    // ---------------------------------------------------------------------
    // 3. A VALID request whose dispatch throws PersistenceCorruptException
    //    must NOT be reported as INVALID_JSON.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task
        ValidRequest_DownstreamPersistenceCorrupt_IsNotInvalidJson()
    {
        // StateRepository uses BackupRollback: with neither a valid primary nor
        // a valid backup it raises PersistenceCorruptException.
        File.WriteAllText(_statePath, "{ corrupted primary :::: ");
        File.WriteAllText(_statePath + ".bak", "{ corrupted backup :::: ");

        NamedPipeCommandServer server = BuildServer();

        ServiceResponse response = await RoundTripAsync(
            server,
            StatusRequestJson());

        Assert.NotEqual("INVALID_JSON", response.ErrorCode);
        Assert.False(response.Success);
    }

    // ---------------------------------------------------------------------
    // 4. Preserved contract: unsupported protocol version, unchanged code,
    //    no dispatch.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task UnsupportedProtocolVersion_Unchanged_AndDoesNotDispatch()
    {
        NamedPipeCommandServer server = BuildServer();

        ServiceResponse response = await RoundTripAsync(
            server,
            """{"protocolVersion":999,"command":"Status"}""");

        Assert.Equal("UNSUPPORTED_PROTOCOL", response.ErrorCode);
        Assert.False(File.Exists(_statePath + ".quarantine"));
        Assert.False(File.Exists(_statePath + ".bak"));
    }

    // ---------------------------------------------------------------------
    // 5. Downstream exception still records dispatch-failure telemetry with
    //    the REAL exception category.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task
        DownstreamException_RecordsDispatchFailureTelemetry()
    {
        // FailClosed store -> the RAW JsonException (the incident's type).
        File.WriteAllText(
            Path.Combine(_tempDir, "route-inventory.json"),
            "{ this is not valid json :::: ");

        ActivityListenerRecorder recorder = new();
        using IDisposable listener = recorder.Start();

        NamedPipeCommandServer server = BuildServer();

        ServiceResponse response = await RoundTripAsync(
            server,
            StatusRequestJson());

        Assert.False(response.Success);

        Activity? dispatch = recorder.Activities
            .FirstOrDefault(a => a.OperationName == PathVeerActivityNames.IpcDispatch);

        Assert.NotNull(dispatch);

        string? outcome =
            dispatch!.Tags.FirstOrDefault(
                t => t.Key == PathVeerTagNames.Outcome).Value;

        Assert.Equal(PathVeerTagValues.Failure, outcome);

        // The category comes from the exception TYPE (never message text). A
        // raw JsonException must be classified as serialization corruption —
        // proof the REAL category is recorded. The pre-fix build answered
        // INVALID_JSON here and never reached dispatch telemetry at all.
        string expectedCategory =
            TelemetryFailureCategoryMapper.ToCategoryString(
                TelemetryFailureCategoryMapper.Map(
                    new JsonException("corrupt")));

        string? category =
            dispatch.Tags.FirstOrDefault(
                t => t.Key == PathVeerTagNames.FailureCategory).Value;

        Assert.Equal(expectedCategory, category);
    }

    // ---------------------------------------------------------------------
    // 6. The response message never leaks raw persisted state / secrets.
    // ---------------------------------------------------------------------

    [Fact]
    public async Task DownstreamFailure_MessageDoesNotLeakRawState()
    {
        string secretFragment = "SUPER_SECRET_ENROLLMENT_CODE";

        File.WriteAllText(
            _statePath,
            $"{{\"cloud\": {{\"enrollmentCode\": \"{secretFragment}\"}} :::: ");

        NamedPipeCommandServer server = BuildServer();

        ServiceResponse response = await RoundTripAsync(
            server,
            StatusRequestJson());

        Assert.False(response.Success);
        Assert.DoesNotContain(secretFragment, response.Message);
        Assert.DoesNotContain("enrollmentCode", response.Message);
        Assert.DoesNotContain("cloud", response.Message);
    }

    // ---------------------------------------------------------------------

    private static string StatusRequestJson() =>
        JsonSerializer.Serialize(
            new ServiceRequest { Command = PathVeerCommand.Status },
            PathVeerJson.Options);

    /// <summary>
    /// Real named-pipe round trip through the server's public
    /// <see cref="NamedPipeCommandServer.RunAsync"/> — the actual handling
    /// boundary, not a helper.
    /// </summary>
    private async Task<ServiceResponse> RoundTripAsync(
        NamedPipeCommandServer server,
        string requestLine)
    {
        using var cts = new CancellationTokenSource(
            TimeSpan.FromSeconds(20));

        Task serverTask = server.RunAsync(
            [_pipeName],
            cts.Token);

        await using NamedPipeClientStream client =
            new(
                ".",
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

        await client.ConnectAsync(cts.Token);

        await client.WriteAsync(
            Encoding.UTF8.GetBytes(requestLine + "\n"),
            cts.Token);
        await client.FlushAsync(cts.Token);

        string responseLine = await ReadLineAsync(client, cts.Token);

        await cts.CancelAsync();

        try { await serverTask; }
        catch (OperationCanceledException) { /* expected on shutdown */ }

        return JsonSerializer.Deserialize<ServiceResponse>(
            responseLine,
            PathVeerJson.Options)!;
    }

    private static async Task<string> ReadLineAsync(
        NamedPipeClientStream client,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var builder = new StringBuilder();

        while (true)
        {
            int read = await client.ReadAsync(buffer, cancellationToken);
            if (read <= 0) break;

            builder.Append(Encoding.UTF8.GetString(buffer, 0, read));

            int newline = builder.ToString().IndexOf('\n');
            if (newline >= 0)
            {
                return builder.ToString()[..newline].Trim();
            }
        }

        return builder.ToString().Trim();
    }

    /// <summary>
    /// Builds the server with production-equivalent wiring (mirrors
    /// <c>PathVeerWorkerTests</c> and the real composition root). Only the
    /// handlers these tests never invoke are null.
    /// </summary>
    private NamedPipeCommandServer BuildServer() =>
        new(
            BuildServerController(),
            new OperationCoordinator(),
            BuildVpnProvider(),
            null!, // PathVeerDiagnosticsService (unused by these tests)
            null!, // DesiredConfigurationService (unused by these tests)
            null!, // RuntimeCoordinator (unused by these tests)
            null!, // CustomRouteCommandHandler (unused by these tests)
            null!, // RuntimeSnapshotCommandHandler (unused by these tests)
            null!, // PrefixUpdateCheckCommandHandler (unused by these tests)
            null!, // DiagnosticCommandHandler (unused by these tests)
            null!, // ExecutionPreviewCommandHandler (unused by these tests)
            null!, // SupportBundleCommandHandler (unused by these tests)
            null!, // CloudCommandHandler (unused by these tests)
            NullLogger<NamedPipeCommandServer>.Instance);

    private OpenVpnEndpointProvider BuildVpnProvider() =>
        new(
            Path.Combine(_tempDir, "vpn-profile.ovpn"),
            new OpenVpnProfileParser(),
            new VpnEndpointResolver());

    private PathVeerController BuildServerController()
    {
        StateRepository stateRepository = new(_statePath);
        RouteInventoryStore routeInventory = new(
            Path.Combine(_tempDir, "route-inventory.json"));
        VpnEndpointInventoryStore endpointInventory = new(
            Path.Combine(_tempDir, "endpoint-inventory.json"));

        CountryPrefixStore prefixStore = new(
            Path.Combine(_tempDir, "prefixes"));

        IReadOnlyList<string> seed = ["203.0.113.0/24"];
        prefixStore.SavePrefixesAsync(
            DirectCountryCode.Parse("IR"), seed).Wait();
        prefixStore.SavePrefixesAsync(
            DirectCountryCode.Parse("IQ"), seed).Wait();

        FakeRouteManager routeManager = new();
        GatewayDetector gatewayDetector = new();
        OpenVpnEndpointProvider vpnProvider = BuildVpnProvider();
        VpnEndpointRouteManager vpnRouteManager = new(routeManager);

        FakeDecisionBuilder decisionBuilder = new();
        RuntimeCycleCoordinator coordinator = new(decisionBuilder);

        return new PathVeerController(
            new FakeCountryPrefixSource(seed),
            prefixStore,
            gatewayDetector,
            routeManager,
            stateRepository,
            routeInventory,
            vpnProvider,
            vpnRouteManager,
            endpointInventory,
            coordinator,
            new FakeExecutor(),
            BuildConfigurationService(),
            new RuntimeOperationStatus(),
            RuntimeCycleProfiler.Noop);
    }

    private DesiredConfigurationService BuildConfigurationService() =>
        new(
            new DesiredConfigurationStore(
                Path.Combine(_tempDir, "desired-configuration.json"),
                new DesiredConfigurationValidator()));

    // ---- minimal fakes (mirrors PathVeerWorkerTests conventions) ---------

    private sealed class FakeExecutor : IRuntimeExecutor
    {
        public Task<RuntimeExecutionResult> ExecuteAsync(
            RuntimeExecutionPlan plan,
            IProgress<RuntimeExecutionProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                RuntimeExecutionResult.NoExecutionRequired());
        }
    }

    private sealed class FakeRouteManager : IRouteManager
    {
        public Task<IReadOnlyList<SystemRoute>> GetIpv4RoutesAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SystemRoute>>(
                Array.Empty<SystemRoute>());

        public Task AddRoutesAsync(
            IReadOnlyCollection<ManagedRoute> routes,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task DeleteRoutesAsync(
            IReadOnlyCollection<ManagedRoute> routes,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeDecisionBuilder : IRuntimeDecisionBuilder
    {
        public Task<RuntimeDecision> BuildAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(BuildDecision(enabled: false));
        }
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

    private sealed class FakeCountryPrefixSource : ICountryPrefixSource
    {
        private readonly IReadOnlyList<string> _prefixes;

        public FakeCountryPrefixSource(IReadOnlyList<string> prefixes)
            => _prefixes = prefixes;

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
            Task.FromResult(
                new PrefixSourceFetchResult
                {
                    Source = GetDescriptor(country),
                    Prefixes = _prefixes,
                    ContentHash = "fake-hash",
                    CountryCode = country
                });
    }

    /// <summary>
    /// Captures Activities so the dispatch-failure telemetry assertion can read
    /// the real emitted tags.
    /// </summary>
    private sealed class ActivityListenerRecorder
    {
        public List<Activity> Activities { get; } = [];

        public IDisposable Start()
        {
            var listener = new ActivityListener
            {
                // Scope to the ONE span this test asserts on. A listener that
                // samples every source (AllDataAndRecorded) globally perturbs
                // the sampling assertions in ObservabilityIntegrationTests when
                // they run in the same process.
                ShouldListenTo = source =>
                    source.Name ==
                    typeof(PathVeerTelemetry).Assembly.GetName().Name,
                Sample = (
                    ref ActivityCreationOptions<ActivityContext> options) =>
                    options.Source.Name == "PathVeer.Core" &&
                    options.Name == PathVeerActivityNames.IpcDispatch
                        ? ActivitySamplingResult.AllDataAndRecorded
                        : ActivitySamplingResult.None,
                ActivityStopped = activity =>
                {
                    lock (Activities)
                    {
                        Activities.Add(activity);
                    }
                }
            };

            ActivitySource.AddActivityListener(listener);
            return new Subscription(listener);
        }

        private sealed class Subscription : IDisposable
        {
            private readonly ActivityListener _listener;

            public Subscription(ActivityListener listener)
                => _listener = listener;

            public void Dispose() => _listener.Dispose();
        }
    }
}
