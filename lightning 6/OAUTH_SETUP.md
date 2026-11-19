# Lightning social sign-in setup

Lightning now has OAuth sign-in handlers for Google, Facebook, X/Twitter, Discord and Hugging Face. Each provider must be configured by the site owner before its button can authenticate users.

## Redirect URI

Register this exact callback URL with every OAuth application:

`https://lightning-ai-6.ray-collier264.workers.dev/oauth/callback`

If Lightning is later served from a custom domain, register that domain's matching `/oauth/callback` URL as well. The Worker uses the hostname on which the sign-in was started.

## Cloudflare Worker variables and secrets

In Cloudflare, open the `lightning-ai-6` Worker, then Settings → Variables and Secrets. Add the following names:

| Provider | Client ID variable | Client secret |
| --- | --- | --- |
| Google | `GOOGLE_CLIENT_ID` | `GOOGLE_CLIENT_SECRET` |
| Facebook | `FACEBOOK_CLIENT_ID` | `FACEBOOK_CLIENT_SECRET` |
| X / Twitter | `TWITTER_CLIENT_ID` | `TWITTER_CLIENT_SECRET` |
| Discord | `DISCORD_CLIENT_ID` | `DISCORD_CLIENT_SECRET` |
| Hugging Face | `HF_CLIENT_ID` | `HF_CLIENT_SECRET` (optional for a public PKCE app) |

Store each client secret as a **Secret**, not as a plain text variable. Client IDs may be plain text variables. Never commit provider secrets to GitHub or put them in the browser.

## Provider app settings

- **Google:** Create a Web application OAuth client. Add the redirect URI above to its authorised redirect URIs. Request the standard `openid email profile` scopes.
- **Facebook:** Add the Facebook Login product to your Meta app, enable web OAuth, and add the redirect URI to Valid OAuth Redirect URIs. Lightning requests `public_profile,email`.
- **X / Twitter:** Create an OAuth 2.0 app using Authorization Code with PKCE. Add the callback URI and allow the `users.read` scope.
- **Discord:** Create an OAuth2 application and add the callback URI under Redirects. Lightning requests `identify email`.
- **Hugging Face:** Create an OAuth application and add the callback URI. Enable `openid profile email`. Public PKCE apps can omit the client secret.

After adding credentials, redeploy or restart the Worker if your Cloudflare dashboard requires it. Reopen Lightning's sign-in dialog; configured providers will be marked as ready.

## EdPass

EdPass is not configured as a generic OAuth provider. A real EdPass login requires an approved integration and the Department for Education's supported SSO protocol, issuer/metadata, and client registration. The EdPass button remains disabled until those details are formally provided.

## Account behaviour

OAuth sign-in creates or reuses a Lightning account using that provider's stable account ID. It does not merge separate provider accounts based only on matching email addresses. Signed-in users can choose **Connect another sign-in method** to link additional providers to their existing Lightning account.

The OAuth state is short-lived, stored hashed in D1, and checked against a secure, HttpOnly browser cookie during the callback.
