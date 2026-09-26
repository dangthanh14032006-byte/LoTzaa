using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;

namespace SecureChat.Web.Services;

public class NameUserIdProvider : IUserIdProvider
{
    public string? GetUserId(HubConnectionContext connection)
    {
        return connection.User?.Identity?.Name;
    }
}
