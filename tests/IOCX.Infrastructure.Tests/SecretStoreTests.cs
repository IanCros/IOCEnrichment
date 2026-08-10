namespace IOCX.Infrastructure.Tests;

using IOCX.Domain;
using IOCX.Infrastructure.Security;

/// <summary>
/// Credential storage. No real API key appears here. The values are obviously fake.
/// </summary>
public class SecretStoreTests
{
    private const string FakeKey = "not-a-real-key-0000";

    [Fact]
    public void InMemoryStore_RoundTripsSecret()
    {
        var store = new InMemorySecretStore();

        Assert.False(store.Has("TEST_KEY"));

        store.Set("TEST_KEY", FakeKey);

        Assert.True(store.Has("TEST_KEY"));
        Assert.Equal(FakeKey, store.Get("TEST_KEY"));
    }

    [Fact]
    public void InMemoryStore_DeleteRemovesSecret()
    {
        var store = new InMemorySecretStore();
        store.Set("TEST_KEY", FakeKey);

        store.Delete("TEST_KEY");

        Assert.False(store.Has("TEST_KEY"));
        Assert.Null(store.Get("TEST_KEY"));
    }

    [Fact]
    public void InMemoryStore_TreatsWhitespaceAsAbsent()
    {
        var store = new InMemorySecretStore();
        store.Set("TEST_KEY", "   ");

        Assert.False(store.Has("TEST_KEY"));
    }

    [Fact]
    public void EnvironmentStore_IsReadOnly()
    {
        var store = new EnvironmentSecretStore();

        Assert.False(store.IsWritable);
        Assert.Throws<NotSupportedException>(() => store.Set("TEST_KEY", FakeKey));
        Assert.Throws<NotSupportedException>(() => store.Delete("TEST_KEY"));
    }

    [Fact]
    public void EnvironmentStore_ReadsProcessVariable()
    {
        const string name = "IOCX_TEST_SECRET_STORE_VAR";
        Environment.SetEnvironmentVariable(name, FakeKey);

        try
        {
            var store = new EnvironmentSecretStore();

            Assert.True(store.Has(name));
            Assert.Equal(FakeKey, store.Get(name));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void Composite_PrefersEnvironmentOverLocalStorage()
    {
        const string name = "IOCX_TEST_PRECEDENCE_VAR";
        Environment.SetEnvironmentVariable(name, "from-environment");

        try
        {
            var local = new InMemorySecretStore();
            local.Set(name, "from-local-storage");

            var composite = new CompositeSecretStore(new EnvironmentSecretStore(), local);

            Assert.Equal("from-environment", composite.Get(name));
            Assert.True(composite.IsSuppliedByEnvironment(name));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void Composite_FallsBackToLocalStorageWhenEnvironmentUnset()
    {
        var local = new InMemorySecretStore();
        local.Set("UNSET_IN_ENVIRONMENT", FakeKey);

        var composite = new CompositeSecretStore(new EnvironmentSecretStore(), local);

        Assert.Equal(FakeKey, composite.Get("UNSET_IN_ENVIRONMENT"));
        Assert.False(composite.IsSuppliedByEnvironment("UNSET_IN_ENVIRONMENT"));
    }

    [Fact]
    public void Composite_WritesToFirstWritableStore()
    {
        var local = new InMemorySecretStore();
        var composite = new CompositeSecretStore(new EnvironmentSecretStore(), local);

        composite.Set("WRITTEN_KEY", FakeKey);

        // The environment store is read-only, so the write must have landed in local storage.
        Assert.Equal(FakeKey, local.Get("WRITTEN_KEY"));
    }

    [Fact]
    public void Composite_RequiresAtLeastOneStore()
    {
        Assert.Throws<ArgumentException>(() => new CompositeSecretStore());
    }

    [Fact]
    public void Factory_ProducesUsableStoreOnAnyPlatform()
    {
        ISecretStore store = SecretStoreFactory.Create(
            Path.Combine(Path.GetTempPath(), $"iocx-test-{Guid.NewGuid():N}.dat"));

        Assert.True(store.IsWritable);
        Assert.False(store.Has("NEVER_SET"));
    }

    [WindowsOnlyFact]
    public void DpapiStore_RoundTripsThroughEncryptedFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"iocx-test-{Guid.NewGuid():N}.dat");

        try
        {
            var store = new DpapiSecretStore(path);
            store.Set("VT_API_KEY", FakeKey);

            // A separate instance proves the value survived the round trip to disk.
            var reopened = new DpapiSecretStore(path);
            Assert.Equal(FakeKey, reopened.Get("VT_API_KEY"));

            // The key must not be recoverable from the raw bytes.
            var raw = File.ReadAllBytes(path);
            Assert.DoesNotContain(FakeKey, System.Text.Encoding.UTF8.GetString(raw));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}

/// <summary>
/// A fact that is skipped off Windows, used for the DPAPI-backed store so the suite
/// still passes on Linux CI runners.
/// </summary>
public sealed class WindowsOnlyFactAttribute : FactAttribute
{
    public WindowsOnlyFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "DPAPI is only available on Windows.";
        }
    }
}
