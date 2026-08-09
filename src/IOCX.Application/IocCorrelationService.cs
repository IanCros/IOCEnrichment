namespace IOCX.Application;

using IOCX.Domain;

/// <summary>Default implementation of IOC correlation service.</summary>
public sealed class IocCorrelationService : IIocCorrelationService
{
    public IReadOnlyCollection<IocRelationship> Correlate(Ioc ioc, IReadOnlyCollection<ProviderResult> results)
    {
        if (ioc == null) throw new ArgumentNullException(nameof(ioc));
        if (results == null) throw new ArgumentNullException(nameof(results));

        var relationships = new List<IocRelationship>();
        var seen = new HashSet<(Guid, Guid, RelationshipType)>();

        void AddRelationship(Guid targetId, RelationshipType type, int confidence, string provider)
        {
            if (targetId == Guid.Empty || targetId == ioc.Id) return;
            var key = (ioc.Id, targetId, type);
            if (seen.Add(key))
            {
                relationships.Add(new IocRelationship(ioc.Id, targetId, type, confidence, provider, DateTimeOffset.UtcNow));
            }
        }

        foreach (var result in results)
        {
            if (result.Status != ProviderStatus.Success || string.IsNullOrEmpty(result.NormalizedData)) continue;

            var data = result.NormalizedData;
            var provider = result.ProviderName;

            // DNS A records -> ResolvesTo
            if (provider == "DNS" && ioc.Type == IocType.Domain && data.Contains("A:", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var line in data.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (line.StartsWith("A:", StringComparison.OrdinalIgnoreCase)) continue;
                    if (System.Net.IPAddress.TryParse(line, out _))
                    {
                        AddRelationship(Guid.NewGuid(), RelationshipType.ResolvesTo, 90, provider);
                    }
                }
            }

            // Malware associations
            if (data.Contains("Malware:", StringComparison.OrdinalIgnoreCase) || data.Contains("malware", StringComparison.OrdinalIgnoreCase))
            {
                AddRelationship(Guid.NewGuid(), RelationshipType.AssociatedWithMalware, 70, provider);
            }

            // URL hosted on domain
            if (ioc.Type == IocType.Url && data.Contains("Host:", StringComparison.OrdinalIgnoreCase))
            {
                AddRelationship(Guid.NewGuid(), RelationshipType.HostedOn, 80, provider);
            }

            // Shodan service exposure
            if (provider == "Shodan" && data.Contains("Port", StringComparison.OrdinalIgnoreCase))
            {
                AddRelationship(Guid.NewGuid(), RelationshipType.ExposesService, 60, provider);
            }

            // RDAP nameservers
            if (provider == "RDAP" && data.Contains("Nameservers:", StringComparison.OrdinalIgnoreCase))
            {
                AddRelationship(Guid.NewGuid(), RelationshipType.HasNameserver, 85, provider);
            }
        }

        return relationships;
    }
}
