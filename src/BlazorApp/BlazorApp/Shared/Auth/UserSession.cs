using System.Security.Claims;

namespace BlazorApp.Shared.Auth
{
    public class UserSession
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Role {  get; set; }
    }
}
