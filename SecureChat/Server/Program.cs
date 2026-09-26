using SecureChat.Server;

int port = args.Length > 0 && int.TryParse(args[0], out var p) ? p : 5050;
string dataDir = Path.Combine(AppContext.BaseDirectory, "server-data");

Console.WriteLine("=== SecureChat Server ===");
Console.WriteLine($"Thư mục dữ liệu: {dataDir}");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

var server = new ChatServer(port, dataDir);
await server.RunAsync(cts.Token);
