# Lightning social sign-in setup

Lightning's sign-in screen is limited to Apple, Microsoft, GitHub, Google and Reddit. Each provider must be configured before its button becomes active.

## Redirect URI

Register this exact callback URL with every OAuth application:

`https://lightning-ai-6.ray-collier264.workers.dev/oauth/callback`

If Lightning is later served from a custom domain, register that domain's matching `/oauth/callback` URL as well.

## Cloudflare Worker variables and secrets

In Cloudflare, open the `lightning-ai-6` Worker, then Settings → Variables and Secrets. Add:

| Provider | Client ID variable | Client secret |
| --- | --- | --- |
| Apple | Not enabled yet | Requires Apple-specific signed client-secret JWT support |
| Microsoft | `MICROSOFT_CLIENT_ID` | `MICROSOFT_CLIENT_SECRET` |
| GitHub | `GITHUB_CLIENT_ID` | `GITHUB_CLIENT_SECRET` |
| Google | `GOOGLE_CLIENT_ID` | `GOOGLE_CLIENT_SECRET` |
| Reddit | `REDDIT_CLIENT_ID` | `REDDIT_CLIENT_SECRET` |

Store client secrets as **Secrets**, not plain text variables. Never commit secrets to GitHub or put them in browser code.

## Provider app settings

Use the callback URI above for each web application.

- **Microsoft:** Register a Web platform redirect URI. The app uses the Microsoft identity platform's common v2 endpoint and requests OpenID Connect plus `User.Read`.
- **GitHub:** Create an OAuth App and set its Authorization callback URL to the callback URI. Lightning requests `read:user` and `user:email`.
- **Google:** Create a Web application OAuth client and add the callback URI to authorised redirect URIs. Lightning requests `openid email profile`.
- **Reddit:** Create a Reddit web app with the callback URI as its redirect URI. Lightning requests the `identity` scope.

## Apple

Apple's web sign-in requires a Services ID, Team ID, Key ID, private signing key and a short-lived ES256 client-secret JWT. The current generic OAuth handler does not yet generate or validate Apple's identity token, so the Apple logo is shown but remains disabled until that dedicated support is implemented. Do not enter an Apple private key into the generic client-secret field.

## Account behaviour

OAuth sign-in uses each provider's stable account ID. It does not merge separate provider accounts just because their email addresses match. Users can link additional methods to an existing Lightning account while signed in.
