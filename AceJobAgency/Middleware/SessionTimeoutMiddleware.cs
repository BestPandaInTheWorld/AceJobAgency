using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace AceJobAgency.Middleware
{
    public class SessionTimeoutMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionTimeoutMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip for login, register, and static files
            var path = context.Request.Path.Value?.ToLower();
            if (path != null && (
                path.Contains("/login") ||
                path.Contains("/register") ||
                path.Contains("/error") ||
                path.Contains("/css") ||
                path.Contains("/js") ||
                path.Contains("/lib") ||
                path.Contains("/favicon")))
            {
                await _next(context);
                return;
            }

            // Check if user is authenticated but session is missing
            if (context.User.Identity?.IsAuthenticated == true)
            {
                var sessionId = context.Session.GetString("SessionId");
                if (string.IsNullOrEmpty(sessionId))
                {
                    // Session expired - redirect to login
                    context.Response.Redirect("/Login?timeout=true");
                    return;
                }
            }

            await _next(context);
        }
    }
}