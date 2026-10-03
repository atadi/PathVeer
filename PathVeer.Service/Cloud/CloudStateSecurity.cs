using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

// The unit-test assembly inspects the pure descriptor logic
// (IsCanonicalSecurityDescriptor) without persisting SYSTEM ownership onto
// real filesystem objects. No production behavior is exposed solely for tests.
[assembly: InternalsVisibleTo("PathVeer.Service.Tests")]

namespace PathVeer.Service.Cloud;

/// <summary>
/// Hardens the on-disk boundary around the PathVeer Cloud device credential.
///
/// The Cloud credential is the single most sensitive secret PathVeer holds.
/// Two independent controls protect it:
///
///   1. Cryptographic scope — the Windows DPAPI protector uses
///      <see cref="DataProtectionScope.CurrentUser"/>. Because the PathVeer
///      Service runs as LocalSystem, "current user" is the LocalSystem
///      profile; ordinary local users therefore CANNOT decrypt the blob even
///      if they obtain its bytes.
///
///   2. Filesystem ACL — this helper enforces a CANONICAL security descriptor
///      on the dedicated Cloud state directory and its files. The canonical
///      descriptor has exactly two properties:
///
///        (a) OWNER = NT AUTHORITY\SYSTEM. A non-SYSTEM owner (including an
///            attacker who pre-created the object) implicitly holds
///            WRITE_DAC and could rewrite the DACL to re-grant themselves
///            access even after the ACE list below is reset, so ownership is
///            part of the boundary.
///
///        (b) DACL = exactly two allow ACEs — NT AUTHORITY\SYSTEM and
///            BUILTIN\Administrators, both FullControl — and NO other
///            discretionary access ACEs. Inheritance is disabled so the
///            permissive %ProgramData%\PathVeer parent ACL (which grants
///            BUILTIN\Users read) cannot leak in, and any attacker-inserted
///            ACE (Everyone, Authenticated Users, BUILTIN\Users, an arbitrary
///            user/group SID, CREATOR OWNER, etc.) is erased by resetting the
///            DACL to the allow-list rather than by maintaining a deny-list.
///
///      Both the owner and the DACL are reset on every invocation, so neither
///      an attacker-controlled owner nor attacker-controlled ACEs can survive.
///
/// Defense in depth: even if one control is somehow bypassed, the other still
/// prevents an ordinary user from obtaining/decrypting the credential merely
/// by reading PathVeer state.
///
/// The helper is idempotent and a no-op on non-Windows platforms. It never
/// touches the SACL/auditing and never weakens ownership or SYSTEM access.
/// </summary>
[SupportedOSPlatform("windows")]
public static class CloudStateSecurity
{
    private static readonly SecurityIdentifier s_system =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier s_administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    // The only SIDs permitted any access in the canonical Cloud DACL.
    private static readonly HashSet<SecurityIdentifier> s_approved =
        new() { s_system, s_administrators };

    /// <summary>
    /// Ensures the Cloud state directory exists and carries the canonical
    /// DACL. Any pre-existing (possibly attacker-controlled) explicit ACEs are
    /// removed; only SYSTEM + Administrators FullControl survive. Existing
    /// files inside the directory are also re-canonicalized. Safe to call
    /// repeatedly.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static void EnsureSecured(string cloudDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cloudDirectory);

        DirectoryInfo dir = Directory.CreateDirectory(cloudDirectory);
        HardenDirectory(dir.FullName);

        // Re-apply to any files already present (e.g. a legacy blob being
        // migrated, or a pre-placed file) so hostile explicit ACEs there are
        // also erased.
        foreach (string file in Directory.EnumerateFiles(dir.FullName))
        {
            HardenFile(file);
        }
    }

    /// <summary>
    /// Canonicalizes the Cloud state directory: resets the DACL to exactly
    /// SYSTEM + Administrators FullControl (inheritance disabled). Used as the
    /// JsonStore "directory prepared" callback so the atomic tmp file is
    /// created inside an already-restricted directory. Idempotent.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static void HardenDirectory(string cloudDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cloudDirectory);

        var info = new DirectoryInfo(cloudDirectory);
        Directory.CreateDirectory(info.FullName);

        var security = info.GetAccessControl();

        // Disable inheritance (drop any inherited ACEs, including the parent
        // %ProgramData%\PathVeer Users-read rule) so the boundary is fully
        // self-contained.
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);

        ApplyCanonicalAcl(security);

        info.SetAccessControl(security);
    }

    /// <summary>
    /// Canonicalizes a single Cloud-state file: resets the DACL to exactly
    /// SYSTEM + Administrators FullControl (inheritance disabled). Used both
    /// for freshly written files (post atomic move) and for migrated or
    /// pre-placed legacy files.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static void HardenFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var info = new FileInfo(filePath);
        var security = info.GetAccessControl();

        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);

        ApplyCanonicalAcl(security);

        info.SetAccessControl(security);
    }

    /// <summary>
    /// Best-effort hardening of a pre-existing legacy credential file
    /// (the original D2 layout under %ProgramData%\PathVeer). Reduces exposure
    /// of the original LocalMachine DPAPI blob (which any local user could
    /// decrypt) by denying ordinary users read access to the bytes while
    /// migration is pending. No-op if the file does not exist.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static void SecureLegacyFileIfPresent(string legacyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(legacyPath);

        if (!File.Exists(legacyPath))
        {
            return;
        }

        try
        {
            HardenFile(legacyPath);
        }
        catch (UnauthorizedAccessException)
        {
            // Hardening is defense-in-depth; the LocalSystem migration still
            // runs. Do not throw over a secondary control.
        }
    }

    /// <summary>
    /// True only when the directory carries the CANONICAL hardened boundary:
    /// owner is SYSTEM, inheritance disabled, and every discretionary allow ACE
    /// is exactly one of the approved identities (SYSTEM, Administrators) with
    /// FullControl. Returns FALSE if ANY unauthorized access ACE survives —
    /// including Everyone, Authenticated Users, BUILTIN\Users, an arbitrary
    /// user/group SID, or CREATOR OWNER — AND FALSE if the owner is not SYSTEM
    /// (a non-SYSTEM owner retains implicit WRITE_DAC and could rewrite the
    /// DACL).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool IsSecured(string cloudDirectory)
    {
        if (!Directory.Exists(cloudDirectory))
        {
            return false;
        }

        var info = new DirectoryInfo(cloudDirectory);
        var security = info.GetAccessControl();

        // Pure descriptor check: the single definition of "canonical" used by
        // both validation (here) and hardening (ApplyCanonicalAcl). An ordinary
        // unit test can exercise this logic against a DirectorySecurity object
        // without ever persisting SYSTEM ownership onto a real object.
        return IsCanonicalSecurityDescriptor(security);
    }

    /// <summary>
    /// Pure validation of a CANONICAL Cloud security descriptor. True only when:
    /// inheritance is disabled; the OWNER is SYSTEM; and the DACL contains
    /// exactly two explicit Allow ACEs: one SYSTEM ACE and one Administrators
    /// ACE. Each ACE must have exactly FileSystemRights.FullControl and the
    /// exact directory/file inheritance and propagation shape emitted by
    /// <see cref="ApplyCanonicalAcl"/>. Any Deny, inherited, duplicate,
    /// unauthorized, extra-rights, or wrongly-shaped ACE makes this FALSE.
    /// This is the SINGLE definition of canonical, shared by <see cref="IsSecured"/>
    /// and <see cref="ApplyCanonicalAcl"/>.
    /// </summary>
    /// <remarks>
    /// Internal (not public) so unit tests can verify descriptor logic without
    /// requiring LocalSystem/SeTakeOwnershipPrivilege on the runner. It does not
    /// touch the filesystem.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    internal static bool IsCanonicalSecurityDescriptor(
        ObjectSecurity security)
    {
        if (security is not FileSystemSecurity fsSecurity)
        {
            return false;
        }

        bool isDirectory = security is DirectorySecurity;
        bool isFile = security is FileSecurity;
        if (!isDirectory && !isFile)
        {
            return false;
        }

        if (!fsSecurity.AreAccessRulesProtected)
        {
            // Inheritance still enabled -> the permissive parent Users-read ACL
            // could leak in.
            return false;
        }

        // The owner implicitly holds WRITE_DAC and can rewrite the DACL even
        // when no ACE grants them access. For this Service-owned secret store
        // the authoritative owner is SYSTEM; any other owner (an ordinary
        // user, Administrators, CREATOR OWNER, arbitrary SID) is not trusted.
        var owner = fsSecurity.GetOwner(typeof(SecurityIdentifier))
            as SecurityIdentifier;
        if (owner == null || owner != s_system)
        {
            return false;
        }

        FileSystemRights canonicalRights = FileSystemRights.FullControl;
        InheritanceFlags canonicalInheritance = isDirectory
            ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
            : InheritanceFlags.None;

        // Validate the raw DACL first. GetAccessRules can coalesce equivalent
        // ACEs, which would hide duplicate physical ACEs and defeat the exact
        // descriptor contract. RawSecurityDescriptor preserves the actual ACE
        // count, qualifier, mask, SID, and inheritance bits.
        var raw = new RawSecurityDescriptor(
            fsSecurity.GetSecurityDescriptorBinaryForm(),
            0);
        if (!IsCanonicalSecurityDescriptor(raw, isDirectory))
        {
            return false;
        }

        // Keep the managed rule view fail-closed as well. In particular, an
        // inherited rule exposed by GetAccessRules is never silently ignored.
        FileSystemAccessRule[] rules = fsSecurity
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        if (rules.Length != 2)
        {
            return false;
        }

        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || rule.IsInherited
                || rule.FileSystemRights != canonicalRights
                || rule.InheritanceFlags != canonicalInheritance
                || rule.PropagationFlags != PropagationFlags.None)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Validates the raw descriptor shape used by the ObjectSecurity overload.
    /// This internal seam lets tests exercise malformed ACEs before Windows
    /// normalizes shapes that cannot exist on a concrete FileSecurity object.
    /// </summary>
    internal static bool IsCanonicalSecurityDescriptor(
        RawSecurityDescriptor security,
        bool isDirectory)
    {
        if ((security.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0
            || security.Owner == null
            || security.Owner != s_system)
        {
            return false;
        }

        RawAcl? dacl = security.DiscretionaryAcl;
        if (dacl == null || dacl.Count != 2)
        {
            return false;
        }

        FileSystemRights canonicalRights = FileSystemRights.FullControl;
        AceFlags canonicalFlags = isDirectory
            ? AceFlags.ContainerInherit | AceFlags.ObjectInherit
            : AceFlags.None;
        bool systemFull = false;
        bool adminFull = false;

        for (int i = 0; i < dacl.Count; i++)
        {
            if (dacl[i] is not CommonAce ace
                || ace.AceQualifier != AceQualifier.AccessAllowed
                || ace.AceFlags != canonicalFlags
                || ace.AccessMask != (int)canonicalRights)
            {
                return false;
            }

            if (ace.SecurityIdentifier == s_system)
            {
                if (systemFull)
                {
                    return false;
                }

                systemFull = true;
            }
            else if (ace.SecurityIdentifier == s_administrators)
            {
                if (adminFull)
                {
                    return false;
                }

                adminFull = true;
            }
            else
            {
                return false;
            }
        }

        return systemFull && adminFull;
    }

    /// <summary>
    /// Resets the DACL to an EMPTY access list, then adds only the approved
    /// identities with FullControl. Resetting (rather than removing a known
    /// deny-list) guarantees no attacker-inserted ACE survives.
    /// </summary>
    private static void ApplyCanonicalAcl(ObjectSecurity security)
    {
        // FileSystemSecurity exposes the public reset/remove API we need.
        var fsSecurity = (FileSystemSecurity)security;

        // ApplyCanonicalAcl is also safe as a standalone canonicalization seam:
        // callers normally protect inheritance immediately before invoking it,
        // but the exact contract requires the helper itself to emit a protected
        // descriptor as well.
        fsSecurity.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);

        // Canonicalize OWNER to SYSTEM. A non-SYSTEM owner (including an
        // attacker who pre-created the object) retains implicit WRITE_DAC and
        // could re-grant themselves access even after the DACL above is
        // reset, so ownership is part of the canonical security descriptor.
        security.SetOwner(s_system);

        // Remove every existing access rule (explicit + inherited) so nothing
        // unauthorized carries over.
        var existing = new List<FileSystemAccessRule>();
        foreach (FileSystemAccessRule rule in
                 fsSecurity.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     typeof(SecurityIdentifier)))
        {
            existing.Add(rule);
        }

        foreach (FileSystemAccessRule rule in existing)
        {
            fsSecurity.RemoveAccessRuleAll(rule);
        }

        if (security is DirectorySecurity ds)
        {
            ds.AddAccessRule(new FileSystemAccessRule(
                s_system,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            ds.AddAccessRule(new FileSystemAccessRule(
                s_administrators,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        else if (security is FileSecurity fsec)
        {
            fsec.AddAccessRule(new FileSystemAccessRule(
                s_system,
                FileSystemRights.FullControl,
                AccessControlType.Allow));
            fsec.AddAccessRule(new FileSystemAccessRule(
                s_administrators,
                FileSystemRights.FullControl,
                AccessControlType.Allow));
        }
    }
}
