using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using PathVeer.Core;
using PathVeer.Core.Configuration;
using PathVeer.Core.CustomRoutes;
using PathVeer.Core.Diagnostics;
using PathVeer.Core.Ipc;
using PathVeer.Core.Routing;
using PathVeer.Core.Runtime;
using PathVeer.Core.Vpn;
using PathVeer.Service.Operations;
using Microsoft.Extensions.Logging;
using PathVeer.Core.Observability.Telemetry;

namespace PathVeer.Service.Ipc;

public class NamedPipeCommandServer
{
    private readonly PathVeerController _controller;
    private readonly OperationCoordinator _operations;
    private readonly OpenVpnEndpointProvider _vpnEndpointProvider;
    private readonly PathVeerDiagnosticsService _diagnosticsService;
    private readonly DesiredConfigurationService _configurationService;
    private readonly RuntimeCoordinator _runtimeCoordinator;
    private readonly CustomRouteCommandHandler _customRoutes;
    private readonly RuntimeSnapshotCommandHandler _runtimeSnapshot;
    private readonly PrefixUpdateCheckCommandHandler
        _prefixUpdateCheck;
    private readonly DiagnosticCommandHandler _diagnosticsHandler;
    private readonly ExecutionPreviewCommandHandler
        _executionPreviewHandler;
    private readonly SupportBundleCommandHandler
        _supportBundleHandler;
    private readonly CloudCommandHandler _cloud;
    private readonly ILogger<NamedPipeCommandServer> _logger;

    public NamedPipeCommandServer(
        PathVeerController controller,
        OperationCoordinator operations,
        OpenVpnEndpointProvider vpnEndpointProvider,
        PathVeerDiagnosticsService diagnosticsService,
        DesiredConfigurationService configurationService,
        RuntimeCoordinator runtimeCoordinator,
        CustomRouteCommandHandler customRoutes,
        RuntimeSnapshotCommandHandler runtimeSnapshot,
        PrefixUpdateCheckCommandHandler prefixUpdateCheck,
        DiagnosticCommandHandler diagnosticsHandler,
        ExecutionPreviewCommandHandler executionPreviewHandler,
        SupportBundleCommandHandler supportBundleHandler,
        CloudCommandHandler cloud,
        ILogger<NamedPipeCommandServer> logger)
    {
        _controller = controller;
        _operations = operations;
        _vpnEndpointProvider = vpnEndpointProvider;
        _diagnosticsService = diagnosticsService;
        _configurationService = configurationService;
        _runtimeCoordinator = runtimeCoordinator;
        _customRoutes = customRoutes;
        _runtimeSnapshot = runtimeSnapshot;
        _prefixUpdateCheck = prefixUpdateCheck;
        _diagnosticsHandler = diagnosticsHandler;
        _executionPreviewHandler = executionPreviewHandler;
        _supportBundleHandler = supportBundleHandler;
        _cloud = cloud;
        _logger = logger;
    }

    public virtual async Task RunAsync(
        CancellationToken cancellationToken)
    {
        await RunAsync(PathVeerPipeNames.AllListenNames, cancellationToken);
    }

    /// <summary>
    /// Internal testing seam: run the SAME listener loop over an explicit set
    /// of pipe names. Production always passes
    /// <see cref="PathVeerPipeNames.AllListenNames"/>; tests pass an isolated
    /// name so they cannot attach to a live PathVeer service on the machine
    /// (which owns the real control pipe). No production behaviour changes —
    /// this only widens where the existing, unmodified loop is pointed.
    /// </summary>
    internal async Task RunAsync(
        IReadOnlyList<string> pipeNames,
        CancellationToken cancellationToken)
    {
        // Dual-listen: both the primary PathVeer pipe and the legacy
        // IranDirect pipe dispatch into the SAME command handler and the SAME
        // OperationCoordinator. There is exactly one authority; the two pipes
        // are two front doors into this single process. Each loop independently
        // accepts clients on its pipe and funnels them through HandleOneClientAsync.
        Task[] listeners = pipeNames
            .Select(name => RunOnePipeAsync(name, cancellationToken))
            .ToArray();

        try
        {
            await Task.WhenAny(listeners);
            await Task.WhenAll(listeners);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            // Expected on shutdown; swallow so the worker can finish cleanly.
        }
    }

    private async Task RunOnePipeAsync(
        string pipeName,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await HandleOneClientAsync(
                    pipeName,
                    cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogError(
                    exception,
                    "Named-pipe '{PipeName}' request failed.",
                    pipeName);

                await Task.Delay(
                    TimeSpan.FromSeconds(1),
                    cancellationToken);
            }
        }
    }

    private async Task HandleOneClientAsync(
        string pipeName,
        CancellationToken cancellationToken)
    {
        await using NamedPipeServerStream pipe =
            NamedPipeServerStreamAcl.Create(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                0,
                0,
                PathVeerPipeSecurity.Build(),
                HandleInheritability.None,
                (PipeAccessRights)0);

        await pipe.WaitForConnectionAsync(
            cancellationToken);

        using StreamReader reader =
            new(
                pipe,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 4096,
                leaveOpen: true);

        using StreamWriter writer =
            new(
                pipe,
                new UTF8Encoding(false),
                bufferSize: 4096,
                leaveOpen: true)
            {
                AutoFlush = true
            };

        string? requestJson =
            await reader.ReadLineAsync(
                cancellationToken);

        // BOUNDARY 1 — INBOUND REQUEST PARSING ONLY.
        //
        // JsonException raised HERE means the caller's request document was not
        // parseable into a ServiceRequest. That, and only that, is INVALID_JSON.
        //
        // ParseRequest contains nothing but deserialization and the
        // shape/version checks that decide WHETHER to dispatch. It never
        // invokes a command handler and never touches persistence, so any
        // JsonException escaping it can only mean the REQUEST was malformed.
        ServiceResponse response;

        ParsedRequest parsed;

        try
        {
            parsed = ParseRequest(
                requestJson ?? string.Empty);
        }
        catch (JsonException exception)
        {
            // Boundary 1 only: the REQUEST document could not be parsed.
            // Malformed request JSON must never dispatch a command, and the log
            // event says exactly that (not "command failed").
            _logger.LogWarning(
                exception,
                "Invalid named-pipe JSON request.");

            response = Failure(
                "INVALID_JSON",
                "The request could not be parsed.");

            goto WriteResponse;
        }

        if (parsed.Rejection is ServiceResponse rejection)
        {
            // A well-formed document that must not be dispatched: unknown
            // protocol version, or a null/absent request body. These keep their
            // established error codes (UNSUPPORTED_PROTOCOL / INVALID_REQUEST)
            // and, like malformed input, never dispatch a command.
            response = rejection;
            goto WriteResponse;
        }

        // BOUNDARY 2 — COMMAND DISPATCH.
        //
        // From here on a ServiceRequest has been produced and validated, so any
        // exception is a genuine COMMAND failure — never malformed input. A
        // downstream JsonException (e.g. a corrupted durable state file
        // surfacing from GetStatusAsync) and a downstream
        // PersistenceCorruptException must NOT be reported as INVALID_JSON:
        // doing so materially misdiagnoses persistence corruption as malformed
        // IPC input.
        try
        {
            response = await ExecuteWithTelemetryAsync(
                parsed.Request!,
                cancellationToken);
        }
        catch (Exception exception)
        {
            // Boundary 2 only: a valid request failed during dispatch. Preserve
            // the established COMMAND_FAILED contract. The real exception
            // category is recorded by IpcDispatchTelemetry.CompleteFailure
            // (exception TYPE, no string/stack-trace inspection) and the full
            // exception is logged server-side; the response message is fixed so
            // raw persisted state, credentials, enrollment codes, or other
            // internal payload content is never echoed to the client.
            _logger.LogError(
                exception,
                "Named-pipe command dispatch failed.");

            response = Failure(
                "COMMAND_FAILED",
                FailureSafeMessage(exception));
        }

    WriteResponse:

        string responseJson =
            JsonSerializer.Serialize(
                response,
                PathVeerJson.Options);

        await writer.WriteLineAsync(
            responseJson.AsMemory(),
            cancellationToken);
    }

    /// <summary>
    /// Outcome of inbound request parsing (BOUNDARY 1).
    ///
    /// <see cref="Rejection"/> is non-null when the document is well-formed but
    /// must NOT be dispatched (unsupported protocol version, or a null/absent
    /// request body). <see cref="Request"/> is non-null when a validated
    /// ServiceRequest is available for dispatch.
    /// </summary>
    internal sealed record ParsedRequest(
        ServiceRequest? Request,
        ServiceResponse? Rejection);

    /// <summary>
    /// BOUNDARY 1 — inbound request parsing ONLY.
    ///
    /// Deserializes the request document and applies the shape/version checks
    /// that decide WHETHER a command may be dispatched. This method never
    /// invokes a command handler and never touches persistence, so a
    /// <see cref="JsonException"/> escaping it can only mean the REQUEST was
    /// malformed — which the caller maps to INVALID_JSON.
    ///
    /// The version/shape outcomes are returned as <see cref="ParsedRequest"/>
    /// rejections (UNSUPPORTED_PROTOCOL / INVALID_REQUEST) so the established
    /// per-outcome error codes are preserved exactly, and — like malformed
    /// input — never dispatch a command. This is an internal testing seam, not
    /// public API.
    /// </summary>
    internal static ParsedRequest ParseRequest(string requestJson)
    {
        ServiceRequest? request =
            JsonSerializer.Deserialize<ServiceRequest>(
                requestJson,
                PathVeerJson.Options);

        if (request is null)
        {
            return new ParsedRequest(
                null,
                new ServiceResponse
                {
                    Success = false,
                    ErrorCode = "INVALID_REQUEST",
                    Message = "The request was invalid."
                });
        }

        if (request.ProtocolVersion != IpcProtocol.CurrentVersion)
        {
            return new ParsedRequest(
                null,
                new ServiceResponse
                {
                    Success = false,
                    ErrorCode = "UNSUPPORTED_PROTOCOL",
                    Message = "Protocol version " +
                        $"{request.ProtocolVersion} is not supported."
                });
        }

        // A validated request. BOUNDARY 2 (dispatch) is the caller's scope, so
        // any downstream exception is handled there — never by the
        // request-parsing INVALID_JSON path.
        return new ParsedRequest(request, null);
    }

    private async Task<ServiceResponse> ExecuteWithTelemetryAsync(
        ServiceRequest request,
        CancellationToken cancellationToken)
    {
        // Independent server-side dispatch span. The named-pipe server runs in
        // a separate process from the client, so this cannot be parented to the
        // client PathVeer.IpcRequest root without changing the wire protocol.
        using IpcDispatchTelemetry.IpcDispatchScope dispatch =
            IpcDispatchTelemetry.Start(request.Command);

        try
        {
            ServiceResponse response = await ExecuteAsync(
                request,
                cancellationToken);
            dispatch.CompleteSuccess();
            return response;
        }
        catch (Exception exception)
        {
            dispatch.CompleteFailure(exception);
            throw;
        }
    }

    private Task<ServiceResponse> ExecuteAsync(
        ServiceRequest request,
        CancellationToken cancellationToken)
    {
        return request.Command switch
        {
            PathVeerCommand.Status =>
                GetStatusAsync(cancellationToken),

            PathVeerCommand.UpdatePrefixes =>
                _operations.ExecuteAsync(
                    UpdatePrefixesAsync,
                    cancellationToken),

            PathVeerCommand.Enable =>
                _operations.ExecuteAsync(
                    EnableAsync,
                    cancellationToken),

            PathVeerCommand.Disable =>
                _operations.ExecuteAsync(
                    DisableAsync,
                    cancellationToken),

            PathVeerCommand.Repair =>
                _operations.ExecuteAsync(
                    RepairAsync,
                    cancellationToken),

            PathVeerCommand.VpnEndpoints =>
                GetVpnEndpointsAsync(cancellationToken),

            PathVeerCommand.Diagnostics =>
                GetDiagnosticsAsync(cancellationToken),

            PathVeerCommand.GetConfiguration =>
                GetConfigurationAsync(cancellationToken),

            PathVeerCommand.SetConfigurationEnabled =>
                SetConfigurationEnabledAsync(
                    request,
                    cancellationToken),

            PathVeerCommand.SetConfigurationProfilePath =>
                SetConfigurationProfilePathAsync(
                    request,
                    cancellationToken),

            PathVeerCommand.SetConfigurationDirectCountry =>
                SetConfigurationDirectCountryAsync(
                    request,
                    cancellationToken),

            PathVeerCommand.RuntimePlan =>
                GetRuntimePlanAsync(cancellationToken),

            PathVeerCommand.CustomRoutesList =>
                _customRoutes.ListAsync(cancellationToken),

            PathVeerCommand.CustomRoutesAddDomain =>
                _customRoutes.AddAsync(
                    CustomRouteEntryType.Domain,
                    request.Value,
                    request.Description,
                    cancellationToken),

            PathVeerCommand.CustomRoutesAddIp =>
                _customRoutes.AddAsync(
                    CustomRouteEntryType.IpAddress,
                    request.Value,
                    request.Description,
                    cancellationToken),

            PathVeerCommand.CustomRoutesAddCidr =>
                _customRoutes.AddAsync(
                    CustomRouteEntryType.Cidr,
                    request.Value,
                    request.Description,
                    cancellationToken),

            PathVeerCommand.CustomRoutesEnable =>
                _customRoutes.SetEnabledAsync(
                    request.Value,
                    enabled: true,
                    cancellationToken),

            PathVeerCommand.CustomRoutesDisable =>
                _customRoutes.SetEnabledAsync(
                    request.Value,
                    enabled: false,
                    cancellationToken),

            PathVeerCommand.CustomRoutesRemove =>
                _customRoutes.RemoveAsync(
                    request.Value,
                    cancellationToken),

            PathVeerCommand.CustomRoutesResolve =>
                _customRoutes.ResolveAsync(cancellationToken),

            PathVeerCommand.CustomRoutesCacheStatus =>
                _customRoutes.CacheStatusAsync(cancellationToken),

            PathVeerCommand.CustomRoutesInvalidateCache =>
                _customRoutes.InvalidateCacheAsync(
                    request.Value,
                    cancellationToken),

            PathVeerCommand.CustomRoutesInvalidateAllCaches =>
                _customRoutes.InvalidateAllCachesAsync(
                    cancellationToken),

            PathVeerCommand.RuntimeSnapshot =>
                _runtimeSnapshot.GetAsync(cancellationToken),

            PathVeerCommand.PrefixUpdateCheckNow =>
                _prefixUpdateCheck.CheckNowAsync(
                    cancellationToken),

            PathVeerCommand.ExecutionPreview =>
                _executionPreviewHandler.GetAsync(
                    cancellationToken),

            PathVeerCommand.SupportBundleExport =>
                _supportBundleHandler.ExportAsync(
                    request.Value ?? string.Empty,
                    cancellationToken),

            PathVeerCommand.CloudEnroll =>
                _cloud.EnrollAsync(
                    request.Value,
                    request.Description,
                    force: request.Force,
                    cancellationToken),

            PathVeerCommand.CloudStatus =>
                _cloud.StatusAsync(cancellationToken),

            PathVeerCommand.CloudReset =>
                _cloud.ResetAsync(cancellationToken),

            _ => Task.FromResult(
                Failure(
                    "UNSUPPORTED_COMMAND",
                    $"Unsupported command: {request.Command}"))
        };
    }

    private async Task<ServiceResponse> GetStatusAsync(
        CancellationToken cancellationToken)
    {
        PathVeerStatus status =
            await _controller.GetStatusAsync(
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message = "Status retrieved.",
            Status = status
        };
    }

    private async Task<ServiceResponse> UpdatePrefixesAsync(
        CancellationToken cancellationToken)
    {
        int count =
            await _controller.UpdatePrefixesAsync(
                country: null,
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message = $"Updated {count} prefixes.",
            PrefixCount = count
        };
    }

    private async Task<ServiceResponse> EnableAsync(
        CancellationToken cancellationToken)
    {
        RuntimeCycleExecutionResult cycleResult =
            await _controller.EnableAsync(
                cancellationToken);

        PathVeerStatus status =
            await _controller.GetStatusAsync(
                cancellationToken);

        return new ServiceResponse
        {
            Success = cycleResult.IsSuccess,
            Message = cycleResult.IsSuccess
                ? "Iran Direct enabled."
                : "Enable failed: "
                  + cycleResult.Execution.ErrorMessage,
            Status = status,
            Decision = cycleResult.Decision,
            Execution = cycleResult.Execution
        };
    }

    private async Task<ServiceResponse> DisableAsync(
        CancellationToken cancellationToken)
    {
        RuntimeCycleExecutionResult cycleResult =
            await _controller.DisableAsync(
                cancellationToken);

        PathVeerStatus status =
            await _controller.GetStatusAsync(
                cancellationToken);

        return new ServiceResponse
        {
            Success = cycleResult.IsSuccess,
            Message = cycleResult.IsSuccess
                ? "Iran Direct disabled."
                : "Disable failed: "
                  + cycleResult.Execution.ErrorMessage,
            Status = status,
            Decision = cycleResult.Decision,
            Execution = cycleResult.Execution
        };
    }

    private async Task<ServiceResponse> RepairAsync(
        CancellationToken cancellationToken)
    {
        await _controller.RepairAsync(
            cancellationToken);

        PathVeerStatus status =
            await _controller.GetStatusAsync(
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message = "Repair completed.",
            Status = status
        };
    }

    private async Task<ServiceResponse>
        GetVpnEndpointsAsync(
            CancellationToken cancellationToken)
    {
        IReadOnlyList<ResolvedVpnEndpoint> endpoints =
            await _vpnEndpointProvider.GetEndpointsAsync(
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message =
                $"Resolved {endpoints.Count} VPN endpoint(s).",
            VpnEndpoints = endpoints
        };
    }

    private async Task<ServiceResponse> GetDiagnosticsAsync(
        CancellationToken cancellationToken)
    {
        PathVeerDiagnostics diagnostics =
            await _diagnosticsService.RunAsync(
                cancellationToken);

        ServiceResponse legacyResponse =
            new ServiceResponse
            {
                Success = true,
                Message =
                    $"Diagnostics completed: " +
                    $"{diagnostics.OverallSeverity}.",
                Diagnostics = diagnostics
            };

        ServiceResponse reportResponse =
            await _diagnosticsHandler.RunAsync(
                cancellationToken);

        return legacyResponse with
        {
            Report = reportResponse.Report
        };
    }
    private async Task<ServiceResponse> GetConfigurationAsync(
        CancellationToken cancellationToken)
    {
        DesiredConfiguration configuration;

        try
        {
            configuration =
                await _configurationService.GetAsync(
                    cancellationToken);
        }
        catch (DesiredConfigurationException exception)
        {
            return Failure(
                "CONFIGURATION_UNAVAILABLE",
                exception.Message);
        }

        return new ServiceResponse
        {
            Success = true,
            Message = "Desired configuration retrieved.",
            Configuration = configuration
        };
    }

    private async Task<ServiceResponse>
        SetConfigurationEnabledAsync(
            ServiceRequest request,
            CancellationToken cancellationToken)
    {
        if (!bool.TryParse(
                request.Value,
                out bool enabled))
        {
            return Failure(
                "INVALID_CONFIGURATION_VALUE",
                "Enabled must be true or false.");
        }

        DesiredConfiguration configuration =
            await _configurationService.SetEnabledAsync(
                enabled,
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message =
                $"Desired configuration enabled set to " +
                $"{enabled}.",
            Configuration = configuration
        };
    }

    private async Task<ServiceResponse>
        SetConfigurationProfilePathAsync(
            ServiceRequest request,
            CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Value))
        {
            return Failure(
                "INVALID_CONFIGURATION_VALUE",
                "VPN profile path is required.");
        }

        DesiredConfiguration configuration =
            await _configurationService.SetProfilePathAsync(
                request.Value,
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message =
                "Desired configuration profile path updated.",
            Configuration = configuration
        };
    }

    private async Task<ServiceResponse>
        SetConfigurationDirectCountryAsync(
            ServiceRequest request,
            CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Value) ||
            !DirectCountryCode.TryParse(
                request.Value,
                out DirectCountryCode? country) ||
            country is null)
        {
            return Failure(
                "INVALID_COUNTRY_CODE",
                "Country code must be a recognized ISO 3166-1 " +
                "alpha-2 country code (e.g. IR, IQ, RO).");
        }

        // Persist requested policy, then refresh that country's prefix
        // dataset. Both run inside the OperationCoordinator so country write,
        // prefix update, and runtime cycle can never mutate shared state
        // concurrently. A failed refresh does NOT roll the config back: the
        // requested policy (country) remains set and reconciliation stays
        // safely blocked until the dataset becomes available.
        return await _operations.ExecuteAsync(
            async ct =>
            {
                DesiredConfiguration configuration =
                    await _configurationService.SetDirectCountryAsync(
                        country,
                        ct);

                bool refreshed;
                string refreshNote;

                try
                {
                    await _controller.UpdatePrefixesAsync(
                        country,
                        ct);

                    refreshed = true;
                    refreshNote =
                        "Prefix dataset updated.";
                }
                catch (Exception exception)
                {
                    refreshed = false;
                    refreshNote =
                        "Prefix dataset update failed: " +
                        exception.Message;
                }

                string message =
                    $"Direct country set to {country.DisplayName} " +
                    $"({country.Code}). {refreshNote}";

                return new ServiceResponse
                {
                    Success = true,
                    Message = message,
                    Configuration = configuration,
                    PrefixRefreshed = refreshed
                };
            },
            cancellationToken);
    }
    private async Task<ServiceResponse> GetRuntimePlanAsync(
        CancellationToken cancellationToken)
    {
        RuntimePlanSnapshot snapshot =
            await _runtimeCoordinator.BuildPlanAsync(
                cancellationToken);

        return new ServiceResponse
        {
            Success = true,
            Message =
                snapshot.Desired.CanReconcile
                    ? "Runtime plan is safe to reconcile."
                    : "Runtime plan contains blockers.",
            RuntimePlan = snapshot
        };
    }
    /// <summary>
    /// Client-facing message for a failed command dispatch.
    ///
    /// Exception messages from the persistence and IPC layers can carry
    /// internal payload content — a <see cref="System.Text.Json.JsonException"/>
    /// on a corrupted store names the offending line and the parsed fragment,
    /// and path/IO messages can expose internal filesystem layout. None of that
    /// belongs on the wire. The real exception (full type, message, stack) is
    /// recorded server-side by the logger and its category by
    /// <c>IpcDispatchTelemetry.CompleteFailure</c>, so operator diagnostics are
    /// preserved without echoing raw state, credentials, or enrollment codes.
    ///
    /// Returns a fixed, category-free sentence: no exception text is inspected
    /// or copied. The persisted <c>COMMAND_FAILED</c> error code is unchanged,
    /// so the public IPC contract is untouched.
    /// </summary>
    private static string FailureSafeMessage(Exception exception) =>
        "The command failed. See the PathVeer service event log for details.";

    private static ServiceResponse Failure(
        string errorCode,
        string message)
    {
        return new ServiceResponse
        {
            Success = false,
            ErrorCode = errorCode,
            Message = message
        };
    }
}