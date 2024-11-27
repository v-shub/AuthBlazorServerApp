using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;

namespace BlazorApp.Shared.Auth
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly ProtectedSessionStorage _sessionStorage;
        private readonly ProtectedLocalStorage _localStorage;
        private ClaimsPrincipal _anonimous = new ClaimsPrincipal(new ClaimsIdentity());
        public CustomAuthenticationStateProvider(ProtectedSessionStorage sessionStorage, ProtectedLocalStorage localStorage)
        {
            _sessionStorage = sessionStorage;
            _localStorage = localStorage;
        }
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var userLocalStorageResult = await _localStorage.GetAsync<UserSession>("UserSession");
                var userLocal = userLocalStorageResult.Success ? userLocalStorageResult.Value : null;
                if(userLocal == null)
                {
                    return await Task.FromResult(new AuthenticationState(_anonimous));
                }
                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.Sid, userLocal.Id),
                    new Claim(ClaimTypes.Name, userLocal.UserName),
                    new Claim(ClaimTypes.Role, userLocal.Role),
                }, "CustomAuth"));
                return await Task.FromResult(new AuthenticationState(claimsPrincipal));
            }
            catch
            {
                return await Task.FromResult(new AuthenticationState(_anonimous));
            }
        }

        public async Task UpdateAuthenticationStateAsync(UserSession userLocal)
        {
            ClaimsPrincipal claimsPrincipal;
            if (userLocal != null)
            {
                await _localStorage.SetAsync("UserSession", userLocal);
                claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.Sid, userLocal.Id),
                    new Claim(ClaimTypes.Name, userLocal.UserName),
                    new Claim(ClaimTypes.Role, userLocal.Role),
                }, "CustomAuth"));
            }
            else
            {
                await _localStorage.DeleteAsync("UserSession");
                claimsPrincipal = _anonimous;
            }
        }
    }
}
