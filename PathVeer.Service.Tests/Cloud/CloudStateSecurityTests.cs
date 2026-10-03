using System.Security.AccessControl;
using System.Security.Principal;
using System.Reflection;
using PathVeer.Service.Cloud;
using Xunit;

namespace PathVeer.Service.Tests.Cloud;

/// <summary>
/// Unit tests for the CANONICAL Cloud security-descriptor definition.
///
/// These tests exercise the pure descriptor logic (the single definition of
/// "canonical" shared by hardening and validation) WITHOUT persisting SYSTEM
/// ownership onto real filesystem objects. That separation is deliberate:
/// assigning the SYSTEM owner requires NT AUTHORITY\SYSTEM authority
/// (SeTakeOwnershipPrivilege / running as LocalSystem), which an ordinary
/// `dotnet test` runner does not have. The actual filesystem persistence of
/// "attacker owner -&gt; SYSTEM owner" is proven by the separate LocalSystem
/// integration tool `tools/certification/Test-PathVeerCloudStateSecurity.ps1`,
/// not by these unit tests.
///
/// The canonical descriptor is:
///   - OWNER = NT AUTHORITY\SYSTEM (a non-SYSTEM owner retains implicit
///     WRITE_DAC and could rewrite the DACL);
///   - DACL = exactly SYSTEM + Administrators, both FullControl;
///   - inheritance disabled (no parent Users-read ACE leaks in).
/// </summary>
public sealed class CloudStateSecurityTests
{
    private static readonly SecurityIdentifier s_users =
        new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier s_everyone =
        new(WellKnownSidType.WorldSid, null);
    private static readonly SecurityIdentifier s_authenticatedUsers =
        new(WellKnownSidType.AuthenticatedUserSid, null);
    private static readonly SecurityIdentifier s_creatorOwner =
        new(WellKnownSidType.CreatorOwnerSid, null);
    private static readonly SecurityIdentifier s_system =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier s_administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    // An ordinary, non-privileged local account SID used to simulate an
    // attacker-inserted explicit ACE or an attacker owner.
    private static readonly SecurityIdentifier s_arbitraryUser =
        new(WellKnownSidType.BuiltinGuestsSid, null);

    // ---- descriptor construction helpers (no filesystem) ----

    private static DirectorySecurity CanonicalDirectoryDescriptor()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_system);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        return ds;
    }

    private static FileSecurity CanonicalFileDescriptor()
    {
        var fs = new FileSecurity();
        fs.SetOwner(s_system);
        fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        fs.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            AccessControlType.Allow));
        fs.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            AccessControlType.Allow));
        return fs;
    }

    // ---- pure descriptor unit tests (no filesystem, no privilege) ----

    [Fact]
    public void IsCanonicalSecurityDescriptor_TrueForSystemOwnerAndSystemAdminFullControl()
    {
        Assert.True(CloudStateSecurity.IsCanonicalSecurityDescriptor(
            CanonicalDirectoryDescriptor()));
        Assert.True(CloudStateSecurity.IsCanonicalSecurityDescriptor(
            CanonicalFileDescriptor()));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForNonSystemOwner()
    {
        // Canonical DACL, but an attacker owns the object -> FALSE. The owner
        // implicitly holds WRITE_DAC and can rewrite the DACL even with no
        // granting ACE, so a non-SYSTEM owner is never "canonical".
        var ds = new DirectorySecurity();
        ds.SetOwner(s_arbitraryUser);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.SetOwner(s_arbitraryUser);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForAdministratorsOwner()
    {
        // The Service store is owned by SYSTEM, not Administrators.
        var ds = new DirectorySecurity();
        ds.SetOwner(s_administrators);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForEveryoneAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_everyone, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForUsersAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_users, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForAuthenticatedUsersAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_authenticatedUsers, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForCreatorOwnerAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_creatorOwner, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForArbitrarySidAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_arbitraryUser, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForInheritanceEnabled()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_system);
        // Inheritance NOT disabled -> the permissive parent ACL could leak in.
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseWhenAdminMissing()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_system);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseWhenSystemMissing()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_system);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseWhenOnlyAdministratorsReadNotFullControl()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_system);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseWhenOnlyReadNotFullControl()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_system);
        ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        ds.AddAccessRule(new FileSystemAccessRule(
            s_administrators, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForEveryoneDenyAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_everyone, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Deny));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForSystemDenyAce()
    {
        var ds = CanonicalDirectoryDescriptor();
        ds.AddAccessRule(new FileSystemAccessRule(
            s_system, FileSystemRights.Read,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Deny));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForSystemWrongInheritanceFlags()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForAdministratorsWrongInheritanceFlags()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ObjectInherit));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForSystemWrongPropagationFlags()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForAdministratorsWrongPropagationFlags()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                PropagationFlags.InheritOnly));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForFileAceWithDirectoryInheritance()
    {
        var raw = RawDescriptorBinary(
            isDirectory: false,
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.FullControl));

        // FileSecurity normalizes directory-only inheritance bits away when the
        // binary descriptor is loaded. Exercise the same production raw-DACL
        // validator before that platform normalization instead.
        Assert.False(
            CloudStateSecurity.IsCanonicalSecurityDescriptor(
                raw, isDirectory: false));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForFileAceWithPropagationFlags()
    {
        var raw = RawDescriptorBinary(
            isDirectory: false,
            Ace(s_system, FileSystemRights.FullControl,
                propagation: PropagationFlags.InheritOnly),
            Ace(s_administrators, FileSystemRights.FullControl));

        Assert.False(
            CloudStateSecurity.IsCanonicalSecurityDescriptor(
                raw, isDirectory: false));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForExtraRightsBeyondFullControl()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system,
                FileSystemRights.FullControl
                | (FileSystemRights)0x40000000,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForDuplicateSystemAce()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            // A second approved SYSTEM identity with a different qualifier
            // remains physically present in the raw DACL and must still be
            // rejected as a duplicate identity.
            Ace(s_system, FileSystemRights.Read,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                type: AccessControlType.Deny));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForDuplicateAdministratorsAce()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit),
            Ace(s_administrators, FileSystemRights.Read,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                type: AccessControlType.Deny));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void IsCanonicalSecurityDescriptor_FalseForInheritedAce()
    {
        var ds = RawDirectoryDescriptor(
            Ace(s_system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit,
                isInherited: true),
            Ace(s_administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit
                | InheritanceFlags.ObjectInherit));

        Assert.False(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void ApplyCanonicalAcl_ProducesExactDirectoryDescriptor()
    {
        var ds = new DirectorySecurity();
        ds.SetOwner(s_arbitraryUser);
        ds.AddAccessRule(new FileSystemAccessRule(
            s_everyone, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit
            | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Deny));

        InvokeApplyCanonicalAcl(ds);

        Assert.True(CloudStateSecurity.IsCanonicalSecurityDescriptor(ds));
    }

    [Fact]
    public void ApplyCanonicalAcl_ProducesExactFileDescriptor()
    {
        var fs = new FileSecurity();
        fs.SetOwner(s_arbitraryUser);
        fs.AddAccessRule(new FileSystemAccessRule(
            s_everyone, FileSystemRights.FullControl,
            AccessControlType.Deny));

        InvokeApplyCanonicalAcl(fs);

        Assert.True(CloudStateSecurity.IsCanonicalSecurityDescriptor(fs));
    }

    private static void InvokeApplyCanonicalAcl(ObjectSecurity security)
    {
        MethodInfo? method = typeof(CloudStateSecurity).GetMethod(
            "ApplyCanonicalAcl",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        method!.Invoke(null, new object[] { security });
    }

    private readonly record struct AceSpec(
        SecurityIdentifier Sid,
        FileSystemRights Rights,
        InheritanceFlags Inheritance,
        PropagationFlags Propagation,
        AccessControlType Type,
        bool IsInherited);

    private static AceSpec Ace(
        SecurityIdentifier sid,
        FileSystemRights rights,
        InheritanceFlags inheritance = InheritanceFlags.None,
        PropagationFlags propagation = PropagationFlags.None,
        AccessControlType type = AccessControlType.Allow,
        bool isInherited = false) =>
        new(sid, rights, inheritance, propagation, type, isInherited);

    private static DirectorySecurity RawDirectoryDescriptor(
        params AceSpec[] aces) =>
        (DirectorySecurity)RawDescriptor(isDirectory: true, aces);

    private static RawSecurityDescriptor RawDescriptorBinary(
        bool isDirectory,
        params AceSpec[] aces) =>
        RawDescriptorBinary(isDirectory, (IReadOnlyList<AceSpec>)aces);

    private static RawSecurityDescriptor RawDescriptorBinary(
        bool isDirectory,
        IReadOnlyList<AceSpec> aces)
    {
        var dacl = new RawAcl(revision: 2, capacity: aces.Count);
        foreach (AceSpec spec in aces)
        {
            AceFlags flags = ToAceFlags(spec);
            AceQualifier qualifier = spec.Type == AccessControlType.Allow
                ? AceQualifier.AccessAllowed
                : AceQualifier.AccessDenied;
            dacl.InsertAce(
                dacl.Count,
                new CommonAce(
                    flags,
                    qualifier,
                    (int)spec.Rights,
                    spec.Sid,
                    isCallback: false,
                    opaque: null));
        }

        return new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent
            | ControlFlags.DiscretionaryAclProtected
            | ControlFlags.SelfRelative,
            s_system,
            s_system,
            systemAcl: null,
            discretionaryAcl: dacl);
    }

    private static FileSystemSecurity RawDescriptor(
        bool isDirectory,
        IReadOnlyList<AceSpec> aces)
    {
        RawSecurityDescriptor descriptor =
            RawDescriptorBinary(isDirectory, aces);
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);

        FileSystemSecurity security = isDirectory
            ? new DirectorySecurity()
            : new FileSecurity();
        security.SetSecurityDescriptorBinaryForm(bytes);
        return security;
    }

    private static AceFlags ToAceFlags(AceSpec spec)
    {
        AceFlags flags = AceFlags.None;
        if (spec.Inheritance.HasFlag(InheritanceFlags.ContainerInherit))
            flags |= AceFlags.ContainerInherit;
        if (spec.Inheritance.HasFlag(InheritanceFlags.ObjectInherit))
            flags |= AceFlags.ObjectInherit;
        if (spec.Propagation.HasFlag(PropagationFlags.NoPropagateInherit))
            flags |= AceFlags.NoPropagateInherit;
        if (spec.Propagation.HasFlag(PropagationFlags.InheritOnly))
            flags |= AceFlags.InheritOnly;
        if (spec.IsInherited)
            flags |= AceFlags.Inherited;
        return flags;
    }
}
