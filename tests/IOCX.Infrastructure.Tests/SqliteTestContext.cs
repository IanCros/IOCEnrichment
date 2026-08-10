namespace IOCX.Infrastructure.Tests;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Creates an <see cref="AppDbContext"/> backed by a real in-memory SQLite database with
/// migrations applied.
/// </summary>
/// <remarks>
/// Deliberately not <c>UseInMemoryDatabase</c>. The EF in-memory provider evaluates LINQ in
/// process, so it happily executes queries the SQLite provider cannot translate — most
/// notably <c>ORDER BY</c> on a <see cref="DateTimeOffset"/> column, which throws at runtime.
/// Testing against the provider the application actually ships with is the only way those
/// failures surface before a user hits them.
/// </remarks>
public sealed class SqliteTestContext : IDisposable
{
    private readonly SqliteConnection _connection;

    public SqliteTestContext()
    {
        // The database lives only as long as the connection is open.
        _connection = new SqliteConnection("Filename=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .Options;

        Context = new AppDbContext(options);
        Context.Database.Migrate();
    }

    public AppDbContext Context { get; }

    /// <summary>Creates an additional context over the same database, to verify persistence.</summary>
    public AppDbContext CreateSeparateContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);

    /// <inheritdoc />
    public void Dispose()
    {
        Context.Dispose();
        _connection.Dispose();
    }
}
