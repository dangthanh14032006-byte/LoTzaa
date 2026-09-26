using System.Text.Json;

namespace SecureChat.Web.Services;

public sealed class ChatGroup
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public List<string> Members { get; set; } = new();
}

public sealed class GroupStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly Dictionary<string, ChatGroup> _groups = new(StringComparer.OrdinalIgnoreCase);

    public GroupStore(string path)
    {
        _path = path;
        Load();
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        var list = JsonSerializer.Deserialize<List<ChatGroup>>(File.ReadAllText(_path)) ?? new();
        foreach (var g in list) _groups[g.Id] = g;
    }

    private void Persist()
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(_path));
        if (dir != null) Directory.CreateDirectory(dir);
        File.WriteAllText(_path, JsonSerializer.Serialize(_groups.Values.ToList(), new JsonSerializerOptions { WriteIndented = true }));
    }

    public ChatGroup Create(string name, string createdBy, List<string> members)
    {
        lock (_lock)
        {
            if (!members.Contains(createdBy, StringComparer.OrdinalIgnoreCase))
                members.Add(createdBy);

            var group = new ChatGroup { Name = name, CreatedBy = createdBy, Members = members };
            _groups[group.Id] = group;
            Persist();
            return group;
        }
    }

    public ChatGroup? Find(string id)
    {
        lock (_lock) { return _groups.TryGetValue(id, out var g) ? g : null; }
    }

    public List<ChatGroup> ForUser(string username)
    {
        lock (_lock)
        {
            return _groups.Values
                .Where(g => g.Members.Any(m => m.Equals(username, StringComparison.OrdinalIgnoreCase)))
                .ToList();
        }
    }
}