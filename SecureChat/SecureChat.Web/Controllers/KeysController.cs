using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureChat.Core.Services;

namespace SecureChat.Web.Controllers;

[Authorize]
[Route("api/keys")]
public class KeysController : Controller
{
    private readonly UserStore _userStore;
    public KeysController(UserStore userStore) => _userStore = userStore;

    [HttpGet("{username}")]
    public IActionResult Get(string username)
    {
        var user = _userStore.Find(username);
        if (user == null || string.IsNullOrEmpty(user.PublicKeyB64))
            return NotFound();
        return Json(new { publicKey = user.PublicKeyB64 });
    }
}