using Microsoft.Identity.Abstractions;

public class AuthorizationMessageHandler : DelegatingHandler
{
    private readonly IAuthorizationHeaderProvider _authorizationHeaderProvider;
    private readonly IConfiguration _configuration;

    public AuthorizationMessageHandler(
        IAuthorizationHeaderProvider authorizationHeaderProvider,
        IConfiguration configuration)
    {
        _authorizationHeaderProvider = authorizationHeaderProvider;
        _configuration = configuration;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Get scopes from configuration
        string[] scopes = [ "api://556d438d-2f4b-4add-9713-ede4e5f5d7da/access_as_user" ];

        // Get the authorization header - this handles all the complexity of token acquisition
        var authHeader = await _authorizationHeaderProvider.CreateAuthorizationHeaderForUserAsync(
            scopes,
            cancellationToken: cancellationToken);

        request.Headers.TryAddWithoutValidation("Authorization", authHeader);

        return await base.SendAsync(request, cancellationToken);
    }
}