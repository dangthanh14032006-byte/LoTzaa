using System.Text.Json;

namespace SecureChat.Web.Services;

public sealed class GroupMessageStore
{
    private readonly string _path;
    private readonly object _lock = new();
    public GroupMessageStore(string path) => _path = path;

    private List<GroupEnvelope> Load()
    {
        if (!File.Exists(_path)) return new();
        var json = File.ReadAllText(_path);
        return string.IsNullOrWhiteSpace(json) ? new() : JsonSerializer.Deserialize<List<GroupEnvelope>>(json) ?? new();
    }

    public void Add(GroupEnvelope envelope)
    {
        lock (_lock)
        {
            var list = Load();
            list.Add(envelope);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            File.WriteAllText(_path, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    public List<GroupEnvelope> GetForGroup(string groupId)
    {
        lock (_lock)
        {
            return Load().Where(e => e.GroupId == groupId).OrderBy(e => e.Timestamp).ToList();
        }
    }
}