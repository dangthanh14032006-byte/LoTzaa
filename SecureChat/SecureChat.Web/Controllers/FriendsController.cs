using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureChat.Core.Services;
using SecureChat.Web.Services;

namespace SecureChat.Web.Controllers;

public sealed class FriendsViewModel
{

    public List<string> Friends { get; init; } = new();
    public List<string> IncomingRequests { get; init; } = new();
    public List<string> Candidates { get; init; } = new();
}

[Authorize]
public sealed class FriendsController : Controller
{
    private readonly UserStore _users;
    private readonly FriendStore _friends;

    public FriendsController(UserStore users, FriendStore friends)
    {
        _users = users;
        _friends = friends;
    }

    [HttpGet]
    public IActionResult Index()
    {
        var me = User.Identity?.Name ?? "";
        var model = new FriendsViewModel
        {
            Friends = _friends.FriendsOf(me),
            IncomingRequests = _friends.IncomingRequests(me),
            Candidates = _users.AllUsernames()
                .Where(name =>
                    !name.Equals(me, StringComparison.OrdinalIgnoreCase) &&
                    _friends.CanRequest(me, name))
                .OrderBy(name => name)
                .ToList()
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Request(string username)
    {
        var me = User.Identity?.Name ?? "";
        var target = _users.Find(username);

        if (target == null)
        {
            TempData["FriendMessage"] = "Không tìm thấy tài khoản này.";
        }
        else if (_friends.Request(me, target.Username))
        {
            TempData["FriendMessage"] = $"Đã gửi lời mời cho {target.Username}.";
        }
        else
        {
            TempData["FriendMessage"] =
                "Không thể gửi lời mời. Có thể bạn đã gửi lời mời hoặc hai người đã là bạn.";
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Accept(string username)
    {
        var me = User.Identity?.Name ?? "";

        TempData["FriendMessage"] = _friends.AcceptRequest(me, username)
            ? $"Đã chấp nhận lời mời của {username}."
            : "Không tìm thấy lời mời đang chờ.";

        return RedirectToAction(nameof(Index));
    }
}
