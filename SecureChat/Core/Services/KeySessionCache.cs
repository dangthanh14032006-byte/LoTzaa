using System.Collections.Concurrent;
using SecureChat.Core.Crypto;

namespace SecureChat.Web.Services;

public sealed class KeySessionCache
{
    private readonly ConcurrentDictionary<string, ElGamalKeyPair> _keys =
        new(StringComparer.OrdinalIgnoreCase);

    public void Set(string username, ElGamalKeyPair keys) => _keys[username] = keys;
    public bool TryGet(string username, out ElGamalKeyPair keys) => _keys.TryGetValue(username, out keys!);
    public void Remove(string username) => _keys.TryRemove(username, out _);
}