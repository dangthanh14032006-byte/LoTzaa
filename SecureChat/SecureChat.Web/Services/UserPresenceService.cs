namespace SecureChat.Web.Services;

public class UserPresenceService
{
    private readonly Dictionary<string, HashSet<string>> _connections =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly object _lock = new();

    public bool UserConnected(string username, string connectionId)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        lock (_lock)
        {
            if (!_connections.TryGetValue(username, out var ids))
            {
                ids = new HashSet<string>();
                _connections[username] = ids;
            }

            bool justCameOnline = ids.Count == 0;
            ids.Add(connectionId);
            return justCameOnline;
        }
    }

    public bool UserDisconnected(string username, string connectionId)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        lock (_lock)
        {
            if (!_connections.TryGetValue(username, out var ids))
                return false;

            ids.Remove(connectionId);

            if (ids.Count > 0)
                return false;

            _connections.Remove(username);
            return true;
        }
    }

    public List<string> GetOnlineUsers()
    {
        lock (_lock)
        {
            return _connections.Keys.ToList();
        }
    }
}