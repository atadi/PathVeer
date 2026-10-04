using PathVeer.Core.Configuration;
using PathVeer.Core.Diagnostics.Runtime;
using PathVeer.Core.Models;
using PathVeer.Core.Networking;
using PathVeer.Core.Prefixes;
using PathVeer.Core.Routing;
using PathVeer.Core.Runtime;
using PathVeer.Core.Runtime.Execution;
using PathVeer.Core.Runtime.Profiling;
using PathVeer.Core.State;
using PathVeer.Core.Observability.Telemetry;
using PathVeer.Core.Vpn;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;

namespace PathVeer.Core;

public sealed class PathVeerController :
    IPathVeerStatusProvider
{
    private const int RouteMetric = 5;

    private readonly ICountryPrefixSource _prefixSource;
    private readonly CountryPrefixStore _prefixStore;
    private readonly GatewayDetector _gatewayDetector;
    private readonly StateRepository _stateRepository;
    private readonly RouteInventoryStore _routeInventoryStore;
    private readonly OpenVpnEndpointProvider _vpnEndpointProvider;
    private readonly VpnEndpointRouteManager _vpnEndpointRouteManager;
    private readonly VpnEndpointInventoryStore
        _vpnEndpointInventoryStore;
    private readonly IRouteManager _routeManager;
    private readonly RuntimeCycleCoordinator
        _runtimeCycleCoordinator;
    private readonly IRuntimeExecutor _runtimeExecutor;
    private readonly DesiredConfigurationService
        _configurationService;
    private readonly RuntimeOperationStatus _operationStatus;
    private readonly RuntimeCycleProfiler _profiler;
    private readonly IPrefixSourceMetadataService?
        _prefixSourceMetadataService;
    private readonly IPrefixSourceUpdateHistoryService?
        _prefixSourceUpdateHistoryService;
    private readonly ILogger<PathVeerController>? _logger;

    public PathVeerController(
        ICountryPrefixSource prefixSource,
        CountryPrefixStore prefixStore,
        GatewayDetector gatewayDetector,
        IRouteManager routeManager,
        StateRepository stateRepository,
        RouteInventoryStore routeInventoryStore,
        OpenVpnEndpointProvider vpnEndpointProvider,
        VpnEndpointRouteManager vpnEndpointRouteManager,
        VpnEndpointInventoryStore vpnEndpointInventoryStore,
        RuntimeCycleCoordinator runtimeCycleCoordinator,
        IRuntimeExecutor runtimeExecutor,
        DesiredConfigurationService configurationService,
        RuntimeOperationStatus operationStatus,
        RuntimeCycleProfiler? profiler = null,
        IPrefixSourceMetadataService? prefixSourceMetadataService =
            null,
        IPrefixSourceUpdateHistoryService?
            prefixSourceUpdateHistoryService = null,
        ILogger<PathVeerController>? logger = null)
    {
        _prefixSource = prefixSource;
        _prefixStore = prefixStore;
        _gatewayDetector = gatewayDetector;
        _stateRepository = stateRepository;
        _routeInventoryStore = routeInventoryStore;
        _vpnEndpointProvider = vpnEndpointProvider;
        _vpnEndpointRouteManager = vpnEndpointRouteManager;
        _vpnEndpointInventoryStore =
            vpnEndpointInventoryStore;
        _routeManager = routeManager;
        _runtimeCycleCoordinator = runtimeCycleCoordinator;
        _runtimeExecutor = runtimeExecutor;
        _configurationService = configurationService;
        _operationStatus = operationStatus;
        _profiler = profiler ?? RuntimeCycleProfiler.Noop;
        _prefixSourceMetadataService =
            prefixSourceMetadataService;
        _prefixSourceUpdateHistoryService =
            prefixSourceUpdateHistoryService;
        _logger = logger;
    }

    public async Task<int> UpdatePrefixesAsync(
        DirectCountryCode? country = null,
        CancellationToken cancellationToken = default)
    {
        DirectCountryCode selected = await ResolveCountryAsync(
            country, cancellationToken);

        PrefixSourceFetchResult fetch;

        try
        {
            fetch = await _prefixSource.FetchAsync(
                selected,
                cancellationToken);
        }
        catch (Exception exception)
        {
            await TryRecordMetadataFailureAsync(
                selected,
                exception,
                cancellationToken);

            await TryRecordHistoryFailureAsync(
                selected,
                exception,
                cancellationToken);

            throw;
        }

        IReadOnlyList<string> previousPrefixes =
            await _prefixStore.LoadPrefixesAsync(
                selected,
                cancellationToken);

        if (!fetch.NotModified)
        {
            await _prefixStore.SavePrefixesAsync(
                selected,
                fetch.Prefixes,
                cancellationToken);
        }

        await TryRecordMetadataSuccessAsync(
            selected,
            fetch,
            previousPrefixes,
            cancellationToken);

        await TryRecordHistorySuccessAsync(
            selected,
            fetch,
            previousPrefixes,
            cancellationToken);

        PathVeerState state =
            await _stateRepository.LoadAsync(
                cancellationToken);

        await _stateRepository.SaveAsync(
            state with
            {
                PrefixCount = fetch.Prefixes.Count,
                PrefixesUpdatedAt =
                    DateTimeOffset.UtcNow,
                LastError = null
            },
            cancellationToken);

        return fetch.Prefixes.Count;
    }

    private async Task<DirectCountryCode> ResolveCountryAsync(
        DirectCountryCode? country,
        CancellationToken cancellationToken)
    {
        if (country is not null)
        {
            return country;
        }

        DesiredConfiguration config =
            await _configurationService.GetAsync(
                cancellationToken);

        return config.DirectCountryCode!;
    }

    private async Task<DirectCountryCode> ResolveCountryOrDefaultAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            DesiredConfiguration config =
                await _configurationService.GetAsync(
                    cancellationToken);

            return config.DirectCountryCode!;
        }
        catch (DesiredConfigurationException)
        {
            return DirectCountryCode.IR;
        }
    }

    private async Task TryRecordMetadataSuccessAsync(
        DirectCountryCode country,
        PrefixSourceFetchResult fetch,
        IReadOnlyList<string> previousPrefixes,
        CancellationToken cancellationToken)
    {
        if (_prefixSourceMetadataService is null)
        {
            return;
        }

        try
        {
            if (fetch.NotModified)
            {
                await _prefixSourceMetadataService
                    .RecordNotModifiedAsync(
                        country,
                        fetch,
                        cancellationToken);
            }
            else
            {
                await _prefixSourceMetadataService
                    .RecordSuccessAsync(
                        country,
                        fetch,
                        previousPrefixes,
                        cancellationToken);
            }
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(
                "Failed to persist prefix source metadata: " +
                "{Error}",
                exception.Message);
        }
    }

    private async Task TryRecordMetadataFailureAsync(
        DirectCountryCode country,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (_prefixSourceMetadataService is null)
        {
            return;
        }

        try
        {
            await _prefixSourceMetadataService
                .RecordFailureAsync(
                    country,
                    _prefixSource.GetDescriptor(country),
                    exception.Message,
                    cancellationToken);
        }
        catch (Exception metadataException)
        {
            _logger?.LogWarning(
                "Failed to persist prefix source failure " +
                "metadata: {Error}",
                metadataException.Message);
        }
    }

    private async Task TryRecordHistorySuccessAsync(
        DirectCountryCode country,
        PrefixSourceFetchResult fetch,
        IReadOnlyList<string> previousPrefixes,
        CancellationToken cancellationToken)
    {
        if (_prefixSourceUpdateHistoryService is null)
        {
            return;
        }

        try
        {
            if (fetch.NotModified)
            {
                PrefixSourceMetadata? current =
                    _prefixSourceMetadataService is null
                        ? null
                        : await _prefixSourceMetadataService
                            .GetCurrentAsync(
                                country,
                                cancellationToken);

                await _prefixSourceUpdateHistoryService
                    .RecordNotModifiedAsync(
                        country,
                        fetch,
                        current?.PrefixCount
                            ?? previousPrefixes.Count,
                        current?.ContentHash,
                        cancellationToken);
            }
            else
            {
                PrefixSourceChangeSummary? changeSummary =
                    _prefixSourceMetadataService is null
                        ? null
                        : await _prefixSourceMetadataService
                            .GetLatestChangeSummaryAsync(
                                country,
                                cancellationToken);

                await _prefixSourceUpdateHistoryService
                    .RecordSuccessAsync(
                        country,
                        fetch,
                        changeSummary,
                        previousPrefixes,
                        cancellationToken);
            }
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(
                "Failed to persist prefix source update history: " +
                "{Error}",
                exception.Message);
        }
    }

    private async Task TryRecordHistoryFailureAsync(
        DirectCountryCode country,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (_prefixSourceUpdateHistoryService is null)
        {
            return;
        }

        try
        {
            await _prefixSourceUpdateHistoryService
                .RecordFailureAsync(
                    country,
                    _prefixSource.GetDescriptor(country),
                    exception.Message,
                    cancellationToken);
        }
        catch (Exception historyException)
        {
            _logger?.LogWarning(
                "Failed to persist prefix source update history: " +
                "{Error}",
                historyException.Message);
        }
    }

    public async Task<RuntimeCycleExecutionResult> EnableAsync(
        CancellationToken cancellationToken = default)
    {
        using IDisposable cycle = _profiler.BeginCycleIfNone("enable");
        using RuntimeCycleTelemetryScope telemetry =
            RuntimeCycleTelemetry.Start(TelemetryTrigger.Forced);

        _operationStatus.Begin(OperationState.Enabling, "user");

        try
        {
            await EnsurePrefixesAsync(
                await ResolveCountryAsync(null, cancellationToken),
                cancellationToken);

            await _configurationService.SetEnabledAsync(
                true, cancellationToken);

            RuntimeCycleExecutionResult result =
                await RunCycleCoreAsync(cancellationToken);
            telemetry.CompleteSuccess(result.Execution.MutatedInfrastructure);
            return result;
        }
        catch (OperationCanceledException)
        {
            telemetry.CompleteCancelled();
            RecordCycleOutcome(
                CycleCompletionStatus.Cancelled,
                "Operation was cancelled.");
            throw;
        }
        catch (Exception ex)
        {
            telemetry.CompleteFailure(ex);
            RecordCycleOutcome(
                CycleCompletionStatus.Failed,
                ex.Message);
            throw;
        }
    }

    public async Task<RuntimeCycleExecutionResult> DisableAsync(
        CancellationToken cancellationToken = default)
    {
        using IDisposable cycle = _profiler.BeginCycleIfNone("disable");
        using RuntimeCycleTelemetryScope telemetry =
            RuntimeCycleTelemetry.Start(TelemetryTrigger.Forced);

        _operationStatus.Begin(OperationState.Disabling, "user");

        try
        {
            await _configurationService.SetEnabledAsync(
                false, cancellationToken);

            RuntimeCycleExecutionResult result =
                await RunCycleCoreAsync(cancellationToken);
            telemetry.CompleteSuccess(result.Execution.MutatedInfrastructure);
            return result;
        }
        catch (OperationCanceledException)
        {
            telemetry.CompleteCancelled();
            RecordCycleOutcome(
                CycleCompletionStatus.Cancelled,
                "Operation was cancelled.");
            throw;
        }
        catch (Exception ex)
        {
            telemetry.CompleteFailure(ex);
            RecordCycleOutcome(
                CycleCompletionStatus.Failed,
                ex.Message);
            throw;
        }
    }

    public async Task<RuntimeCycleExecutionResult> RunCycleAsync(
        CancellationToken cancellationToken = default)
    {
        using IDisposable cycle = _profiler.BeginCycleIfNone("repair");
        using RuntimeCycleTelemetryScope telemetry =
            RuntimeCycleTelemetry.Start(TelemetryTrigger.Repair);

        _operationStatus.Begin(OperationState.Repairing, "cycle");

        try
        {
            RuntimeCycleExecutionResult result =
                await RunCycleCoreAsync(cancellationToken);
            telemetry.CompleteSuccess(result.Execution.MutatedInfrastructure);
            return result;
        }
        catch (OperationCanceledException)
        {
            telemetry.CompleteCancelled();
            RecordCycleOutcome(
                CycleCompletionStatus.Cancelled,
                "Operation was cancelled.");
            throw;
        }
        catch (Exception ex)
        {
            telemetry.CompleteFailure(ex);
            RecordCycleOutcome(
                CycleCompletionStatus.Failed,
                ex.Message);
            throw;
        }
    }

    private async Task ValidateDurableStateAsync(
        CancellationToken cancellationToken)
    {
        _ = await _stateRepository.LoadAsync(cancellationToken);
    }

    private async Task<RuntimeCycleExecutionResult> RunCycleCoreAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Durable runtime state is an execution precondition, not desired
            // state authority. LoadAsync preserves the existing semantics:
            // missing state yields the existing default, valid state succeeds,
            // a corrupt primary may recover from .bak, and unrecoverable
            // corruption propagates before planning or route mutation.
            await ValidateDurableStateAsync(cancellationToken);

            RuntimeDecision decision =
                await _runtimeCycleCoordinator.RunCycleAsync(
                    cancellationToken);

            _operationStatus.SetPlannedSteps(decision.ExecutionPlan.Count);

            RuntimeExecutionResult execution;

            using (RuntimeExecutionTelemetryScope executionTelemetry =
                RuntimeExecutionTelemetry.Start(decision.ExecutionPlan.Count))
            {
                try
                {
                    using (_profiler.Measure(
                        RuntimePerfCategory.ExecutionTotal))
                    {
                        execution =
                            await _runtimeExecutor.ExecuteAsync(
                                decision.ExecutionPlan,
                                _operationStatus,
                                cancellationToken);
                    }

                    _operationStatus.Complete(execution);

                    await UpdateStateAsync(
                        decision, execution, cancellationToken);

                    RecordCycleOutcome(execution, decision);

                    executionTelemetry.Complete(execution);
                }
                catch (OperationCanceledException)
                {
                    executionTelemetry.CompleteCancelled();
                    _operationStatus.Fail("Operation was cancelled.");
                    throw;
                }
                catch (Exception ex)
                {
                    executionTelemetry.CompleteFailure(ex);
                    _operationStatus.Fail(ex.Message);
                    throw;
                }

                return new RuntimeCycleExecutionResult
                {
                    Decision = decision,
                    Execution = execution
                };
            }
        }
        catch (OperationCanceledException)
        {
            _operationStatus.Fail("Operation was cancelled.");
            throw;
        }
        catch (Exception ex)
        {
            _operationStatus.Fail(ex.Message);
            throw;
        }
    }

    private void RecordCycleOutcome(
        RuntimeExecutionResult execution,
        RuntimeDecision decision)
    {
        _profiler.SetCycleOutcome(
            MapCompletionStatus(execution.Status),
            execution.ErrorMessage,
            decision.ExecutionPlan.Count,
            _operationStatus.CompletedSteps);
    }

    private void RecordCycleOutcome(
        CycleCompletionStatus status,
        string error)
    {
        RuntimeOperationSnapshot snapshot =
            _operationStatus.CreateSnapshot();
        _profiler.SetCycleOutcome(
            status,
            error,
            snapshot.PlannedSteps,
            snapshot.CompletedSteps);
    }

    private static CycleCompletionStatus MapCompletionStatus(
        RuntimeExecutionResultStatus status) => status switch
    {
        RuntimeExecutionResultStatus.Completed =>
            CycleCompletionStatus.Completed,
        RuntimeExecutionResultStatus.NoExecutionRequired =>
            CycleCompletionStatus.Completed,
        RuntimeExecutionResultStatus.Planned =>
            CycleCompletionStatus.Completed,
        RuntimeExecutionResultStatus.PartiallyCompleted =>
            CycleCompletionStatus.PartiallyCompleted,
        RuntimeExecutionResultStatus.Failed =>
            CycleCompletionStatus.Failed,
        RuntimeExecutionResultStatus.Cancelled =>
            CycleCompletionStatus.Cancelled,
        _ => CycleCompletionStatus.Failed
    };

    public async Task<PathVeerStatus> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        PathVeerState state =
            await _stateRepository.LoadAsync(
                cancellationToken);

        IReadOnlyList<string> prefixes =
            await _prefixStore.LoadPrefixesAsync(
                await ResolveCountryOrDefaultAsync(cancellationToken),
                cancellationToken);

        RouteInventory inventory =
            await _routeInventoryStore.LoadAsync(
                cancellationToken);

        ManagedRoute[] ownedRoutes =
            ParseInventory(inventory.Routes);

        int installed;

        installed = await CountOwnedRoutesAsync(
            ownedRoutes, cancellationToken);

        VpnEndpointInventory endpointInventory =
            await _vpnEndpointInventoryStore.LoadAsync(
                cancellationToken);

        VpnEndpointProtectionHealth endpointHealth =
            await _vpnEndpointRouteManager.GetHealthAsync(
                endpointInventory.Endpoints,
                cancellationToken);

        // A missing/corrupt authoritative configuration is not a routing
        // fault: the runtime is still observable, but user intent is unknown,
        // so report it as not enabled rather than throwing.
        bool desiredEnabled = false;
        string? requestedCountryCode = null;
        try
        {
            DesiredConfiguration config =
                await _configurationService.GetAsync(
                    cancellationToken);
            desiredEnabled = config.Enabled;
            requestedCountryCode =
                config.DirectCountryCode?.Code;
        }
        catch (DesiredConfigurationException)
        {
            desiredEnabled = false;
        }

        return new PathVeerStatus
        {
            Enabled = state.Enabled,
            DesiredEnabled = desiredEnabled,
            RequestedCountryCode = requestedCountryCode,
            Operation = _operationStatus.CreateSnapshot(),
            Gateway = state.Gateway,
            InterfaceIndex =
                state.InterfaceIndex,
            InterfaceName =
                state.InterfaceName,
            PrefixCount =
                prefixes.Count,
            InstalledRouteCount =
                installed,
            PrefixesUpdatedAt =
                state.PrefixesUpdatedAt,
            LastError =
                state.LastError,
            VpnEndpointCount =
                endpointHealth.CurrentEndpointCount,
            ProtectedVpnEndpointCount =
                endpointHealth.ProtectedEndpointCount,
            VpnEndpointsProtected =
                endpointHealth.IsProtected
        };
    }

    public async Task RepairAsync(
        CancellationToken cancellationToken = default)
    {
        PathVeerState state =
            await _stateRepository.LoadAsync(
                cancellationToken);

        if (!state.Enabled)
        {
            return;
        }

        await RunCycleAsync(cancellationToken);
    }

    private async Task UpdateStateAsync(
        RuntimeDecision decision,
        RuntimeExecutionResult execution,
        CancellationToken cancellationToken)
    {
        PathVeerState state =
            await _stateRepository.LoadAsync(
                cancellationToken);

        bool isSuccess = execution.Status switch
        {
            RuntimeExecutionResultStatus.Completed => true,
            RuntimeExecutionResultStatus.NoExecutionRequired => true,
            RuntimeExecutionResultStatus.PartiallyCompleted => false,
            RuntimeExecutionResultStatus.Failed => false,
            RuntimeExecutionResultStatus.Cancelled => false,
            _ => throw new ArgumentOutOfRangeException(
                nameof(execution.Status), execution.Status, null)
        };

        if (isSuccess)
        {
            if (decision.Plan.Desired.Enabled)
            {
                ObservedDirectGateway? gateway =
                    decision.Plan.Observed.DirectGateway;

                IReadOnlyList<string> prefixes =
                    await _prefixStore.LoadPrefixesAsync(
                        await ResolveCountryOrDefaultAsync(
                            cancellationToken),
                        cancellationToken);

                using (_profiler.Measure(
                    RuntimePerfCategory.PersistenceStateSave))
                {
                    await _stateRepository.SaveAsync(
                        state with
                        {
                            Enabled = true,
                            Gateway = gateway?.Address
                                ?? state.Gateway,
                            InterfaceIndex = gateway?.InterfaceIndex
                                ?? state.InterfaceIndex,
                            InterfaceName = gateway?.InterfaceName
                                ?? state.InterfaceName,
                            PrefixCount = prefixes.Count,
                            EnabledAt = state.EnabledAt
                                ?? DateTimeOffset.UtcNow,
                            PrefixesUpdatedAt =
                                _prefixStore.GetPrefixLastModified(
                                    await ResolveCountryOrDefaultAsync(
                                        cancellationToken)),
                            LastError = null
                        },
                        cancellationToken);
                }
            }
            else
            {
                using (_profiler.Measure(
                    RuntimePerfCategory.PersistenceStateSave))
                {
                    await _stateRepository.SaveAsync(
                        state with
                        {
                            Enabled = false,
                            LastError = null
                        },
                        cancellationToken);
                }

                if (execution.MutatedInfrastructure)
                {
                    using (_profiler.Measure(
                        RuntimePerfCategory.PersistenceInventorySave))
                    {
                        await _routeInventoryStore.ClearAsync(
                            cancellationToken);
                    }
                }
            }
        }
        else
        {
            string failureSummary = BuildFailureSummary(execution);

            using (_profiler.Measure(
                RuntimePerfCategory.PersistenceStateSave))
            {
                await _stateRepository.SaveAsync(
                    state with { LastError = failureSummary },
                    cancellationToken);
            }
        }
    }

    private static string BuildFailureSummary(
        RuntimeExecutionResult execution)
    {
        RuntimeExecutionStepResult[] failedSteps = execution.StepResults
            .Where(sr => sr.Status == RuntimeExecutionStepStatus.Failed)
            .ToArray();

        if (failedSteps.Length == 0)
            return execution.ErrorMessage ?? "Cycle failed.";

        RuntimeExecutionStepResult first = failedSteps[0];

        string target = string.IsNullOrWhiteSpace(
            first.DestinationPrefix)
                ? first.StepIdentity
                : first.DestinationPrefix;

        StringBuilder sb = new();
        sb.AppendLine($"{failedSteps.Length} step(s) failed.");
        sb.AppendLine("First failure:");
        sb.AppendLine($"Type: {first.Kind}");
        sb.AppendLine($"Target: {target}");
        sb.AppendLine($"Reason: {first.ErrorMessage ?? "Unknown error"}");

        return sb.ToString().TrimEnd();
    }

    private static string ToIdentity(SystemRoute route) =>
        $"{route.DestinationPrefix}|" +
        $"{route.NextHop}|" +
        $"{route.InterfaceIndex}";

    private async Task<int> CountOwnedRoutesAsync(
        ManagedRoute[] ownedRoutes,
        CancellationToken cancellationToken)
    {
        if (ownedRoutes.Length == 0)
            return 0;

        IReadOnlyList<SystemRoute> actual =
            await _routeManager.GetIpv4RoutesAsync(
                cancellationToken);

        HashSet<string> actualIdentities = actual
            .Select(ToIdentity)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return ownedRoutes.Count(route =>
            actualIdentities.Contains(route.Identity));
    }

    private static RouteInventoryItem ToInventoryItem(
        ManagedRoute route)
    {
        return new RouteInventoryItem
        {
            DestinationPrefix =
                route.DestinationPrefix,
            Gateway =
                route.Gateway.ToString(),
            InterfaceIndex =
                route.InterfaceIndex,
            Metric = route.Metric
        };
    }

    private static ManagedRoute[] ParseInventory(
        IReadOnlyCollection<RouteInventoryItem> routes)
    {
        List<ManagedRoute> parsed = [];

        foreach (RouteInventoryItem route in routes)
        {
            if (!IPAddress.TryParse(
                    route.Gateway,
                    out IPAddress? gateway))
            {
                continue;
            }

            parsed.Add(
                new ManagedRoute
                {
                    DestinationPrefix =
                        route.DestinationPrefix,
                    Gateway = gateway,
                    InterfaceIndex =
                        route.InterfaceIndex,
                    Metric = route.Metric
                });
        }

        return parsed.ToArray();
    }

    private async Task<IReadOnlyList<string>>
        EnsurePrefixesAsync(
            DirectCountryCode country,
            CancellationToken cancellationToken)
    {
        IReadOnlyList<string> prefixes =
            await _prefixStore.LoadPrefixesAsync(
                country,
                cancellationToken);

        if (prefixes.Count > 0)
        {
            return prefixes;
        }

        await UpdatePrefixesAsync(
            country,
            cancellationToken);

        prefixes =
            await _prefixStore.LoadPrefixesAsync(
                country,
                cancellationToken);

        if (prefixes.Count == 0)
        {
            throw new InvalidOperationException(
                $"No {country.Code} IPv4 prefixes are available.");
        }

        return prefixes;
    }
}
