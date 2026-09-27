using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureChat.Core.Services;
using SecureChat.Web.Services;

namespace SecureChat.Web.Controllers;

[Authorize]
public class ChatController : Controller
{
    private readonly UserStore _userStore;
    private readonly GroupStore _groupStore;
    private readonly FriendStore _friendStore;
    public ChatController(
    UserStore userStore,
    GroupStore groupStore,
    FriendStore friendStore)
    {
        _userStore = userStore;
        _groupStore = groupStore;
        _friendStore = friendStore;
    }

    [HttpGet]
    public IActionResult Index(string? user, string? group)
    {
        string currentUser = User.Identity?.Name ?? "";

        var users = _friendStore.FriendsOf(currentUser)
            .Where(name =>
                !name.Equals(currentUser, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var userAvatars =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var username in users)
        {
            userAvatars[username] =
                _userStore.Find(username)?.AvatarUrl ?? "";
        }

        ViewBag.UserAvatars = userAvatars;
           

        if (!string.IsNullOrWhiteSpace(user))
        {
            var selectedAccount = _userStore.Find(user);

            user = (selectedAccount == null ||
                    !_friendStore.AreFriends(currentUser, selectedAccount.Username))
                ? null
                : selectedAccount.Username;
        }

        ChatGroup? selectedGroup = null;
        if (!string.IsNullOrWhiteSpace(group))
        {
            var g = _groupStore.Find(group);
            if (g != null && g.Members.Any(m => m.Equals(currentUser, StringComparison.OrdinalIgnoreCase)))
                selectedGroup = g;
        }

        ViewBag.CurrentUser = currentUser;
        ViewBag.Users = users;
        ViewBag.SelectedUser = string.IsNullOrWhiteSpace(group) ? user : null;
        ViewBag.Groups = _groupStore.ForUser(currentUser);
        ViewBag.SelectedGroup = selectedGroup;

        return View();
    }

    [HttpGet]
    public IActionResult CreateGroup()
    {
        string currentUser = User.Identity?.Name ?? "";
        ViewBag.Users = _userStore.AllUsernames()
            .Where(u => !u.Equals(currentUser, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return View();
    }

    [HttpPost]
    public IActionResult CreateGroup(string groupName, List<string> members)
    {
        string currentUser = User.Identity?.Name ?? "";

        if (string.IsNullOrWhiteSpace(groupName) || members == null || members.Count == 0)
        {
            ViewBag.Error = "Nhập tên nhóm và chọn ít nhất 1 thành viên.";
            ViewBag.Users = _userStore.AllUsernames()
                .Where(u => !u.Equals(currentUser, StringComparison.OrdinalIgnoreCase))
                .ToList();
            return View();
        }

        var group = _groupStore.Create(groupName, currentUser, members);
        return RedirectToAction("Index", new { group = group.Id });
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult DeleteGroup(string groupId)
    {
        var me = User.Identity?.Name ?? "";
        _groupStore.Delete(groupId, me);
        return RedirectToAction("Index");
    }
}