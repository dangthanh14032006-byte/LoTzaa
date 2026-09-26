using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.SignalR;
using SecureChat.Core.Services;
using SecureChat.Web.Hubs;
using SecureChat.Web.Services;
using SecureChat.Core.Crypto;
using SecureChat.Web.Services;
using System.Globalization;
using Microsoft.AspNetCore.Localization;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLocalization(
    options => options.ResourcesPath = "Resources");

builder.Services
    .AddControllersWithViews()
    .AddViewLocalization()
    .AddDataAnnotationsLocalization();

builder.Services.AddSignalR(options =>
{
    options.MaximumReceiveMessageSize = 3 * 1024 * 1024;
});
// UserStore
var userFile = Path.Combine(
    builder.Environment.ContentRootPath,
    "Data",
    "users.json"
);

builder.Services.AddSingleton<UserStore>(
    new UserStore(userFile)
);
builder.Services.AddSingleton<KeySessionCache>();
builder.Services.AddSingleton<SecureChat.Web.Services.OtpService>();
var messagesFile = Path.Combine(
    builder.Environment.ContentRootPath, "Data", "messages.json");
builder.Services.AddSingleton(new EncryptedMessageStore(messagesFile));

var groupsFile = Path.Combine(builder.Environment.ContentRootPath, "Data", "groups.json");
builder.Services.AddSingleton(new GroupStore(groupsFile));
var friendsFile = Path.Combine(
    builder.Environment.ContentRootPath,
    "Data",
    "friends.json");

builder.Services.AddSingleton(new FriendStore(friendsFile));
var groupMessagesFile = Path.Combine(builder.Environment.ContentRootPath, "Data", "groupMessages.json");
builder.Services.AddSingleton(new GroupMessageStore(groupMessagesFile));
var messageFile = Path.Combine(
    builder.Environment.ContentRootPath,
    "Data",
    "messages.json"
);

builder.Services.AddSingleton<MessageStore>(
    new MessageStore(messageFile)
);
builder.Services.AddSingleton<UserPresenceService>();
builder.Services.AddSingleton<IUserIdProvider, NameUserIdProvider>();
// Authentication
builder.Services
    .AddAuthentication("SecureChatCookie")
    .AddCookie("SecureChatCookie", options =>
    {
        options.LoginPath = "/Account/Login";
    });

builder.Services.AddAuthorization();

var app = builder.Build();
var supportedCultures = new[]
{
    new CultureInfo("vi"),
    new CultureInfo("en")
};

var localizationOptions = new RequestLocalizationOptions
{
    DefaultRequestCulture = new RequestCulture("vi"),
    SupportedCultures = supportedCultures,
    SupportedUICultures = supportedCultures
};

app.UseRequestLocalization(localizationOptions);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}"
);

app.MapHub<ChatHub>("/chatHub");

app.Run();