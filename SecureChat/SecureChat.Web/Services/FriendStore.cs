using System.Text.Json;

namespace SecureChat.Web.Services;

public sealed class FriendRequestRecord
{
    public string Requester { get; set; } = "";
    public string Addressee { get; set; } = "";
    public string Status { get; set; } = "Pending";
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

public sealed class FriendStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public FriendStore(string path)
    {
        _path = path;
    }

    private List<FriendRequestRecord> Load()
    {
        if (!File.Exists(_path))
            return new();

        var json = File.ReadAllText(_path);
        if (string.IsNullOrWhiteSpace(json))
            return new();

        return JsonSerializer.Deserialize<List<FriendRequestRecord>>(
            json, _jsonOptions) ?? new();
    }

    private void Persist(List<FriendRequestRecord> records)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(_path));
        if (directory != null)
            Directory.CreateDirectory(directory);

        File.WriteAllText(_path, JsonSerializer.Serialize(records, _jsonOptions));
    }

    private static bool Same(string left, string right) =>
        left.Equals(right, StringComparison.OrdinalIgnoreCase);

    private static bool Between(
        FriendRequestRecord record,
        string userA,
        string userB) =>
        (Same(record.Requester, userA) && Same(record.Addressee, userB)) ||
        (Same(record.Requester, userB) && Same(record.Addressee, userA));

    public bool CanRequest(string requester, string addressee)
    {
        if (string.IsNullOrWhiteSpace(requester) ||
            string.IsNullOrWhiteSpace(addressee) ||
            Same(requester, addressee))
            return false;

        lock (_lock)
            return !Load().Any(record => Between(record, requester, addressee));
    }

    public bool Request(string requester, string addressee)
    {
        if (string.IsNullOrWhiteSpace(requester) ||
            string.IsNullOrWhiteSpace(addressee) ||
            Same(requester, addressee))
            return false;

        lock (_lock)
        {
            var records = Load();
            if (records.Any(record => Between(record, requester, addressee)))
                return false;

            records.Add(new FriendRequestRecord
            {
                Requester = requester,
                Addressee = addressee,
                Status = "Pending",
                CreatedAtUtc = DateTime.UtcNow
            });

            Persist(records);
            return true;
        }
    }

    public bool AcceptRequest(string currentUser, string requester)
    {
        lock (_lock)
        {
            var records = Load();
            var request = records.FirstOrDefault(record =>
                Same(record.Requester, requester) &&
                Same(record.Addressee, currentUser) &&
                Same(record.Status, "Pending"));

            if (request == null)
                return false;

            request.Status = "Accepted";
            Persist(records);
            return true;
        }
    }

    public bool AreFriends(string userA, string userB)
    {
        lock (_lock)
        {
            return Load().Any(record =>
                Same(record.Status, "Accepted") &&
                Between(record, userA, userB));
        }
    }

    public List<string> FriendsOf(string username)
    {
        lock (_lock)
        {
            var records = Load();
            return records
                .Where(record =>
                    Same(record.Status, "Accepted") &&
                    (Same(record.Requester, username) ||
                     Same(record.Addressee, username)))
                .Select(record =>
                    Same(record.Requester, username)
                        ? record.Addressee
                        : record.Requester)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name)
                .ToList();
        }
    }

    public List<string> IncomingRequests(string username)
    {
        lock (_lock)
        {
            return Load()
                .Where(record =>
                    Same(record.Addressee, username) &&
                    Same(record.Status, "Pending"))
                .Select(record => record.Requester)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name)
                .ToList();
        }
    }
    public bool RemoveFriend(string userA, string userB)
    {
        lock (_lock)
        {
            var records = Load();
            var record = records.FirstOrDefault(r =>
                Same(r.Status, "Accepted") && Between(r, userA, userB));

            if (record == null) return false;

            records.Remove(record);
            Persist(records);
            return true;
        }
    }
}
