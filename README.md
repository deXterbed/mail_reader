# Mail Reader

Mail Reader is a Rails 8 application that authenticates with Google via OAuth,
refreshes tokens automatically, and shows the 10 most recent messages from the
user's Gmail inbox.

## Prerequisites

- Ruby `3.4.2` (see `.ruby-version`)
- Bundler `>= 2.5`
- PostgreSQL 14 or newer available locally
- Google Cloud project with the Gmail API enabled

## Local Setup

1. Install Ruby, Bundler, and PostgreSQL if you have not already.
2. Install gems:
   - `bundle install`
3. Prepare the database (creates and migrates):
   - `bin/rails db:prepare`

### Configure Google OAuth

1. In Google Cloud Console, create an OAuth consent screen (External) and a
   Web application OAuth client.
2. Add `http://localhost:3000/auth/google_oauth2/callback` as an authorized
   redirect URI.
3. Enable the Gmail API for the project.
4. Create an `.env` file (or update your shell environment) and supply:
   ```
   GOOGLE_CLIENT_ID=your_client_id
   GOOGLE_CLIENT_SECRET=your_client_secret
   ```
   `dotenv-rails` loads these values automatically in development/test.

## Running the App

- Start the Rails server: `bin/dev` (preferred) or `bin/rails server`
- Visit `http://localhost:3000`
- Click the **Sign in with Google** link (routes to `/login`) and complete the
  OAuth flow.
- After successful authentication, the dashboard displays the most recent Gmail
  messages, cached for 5 minutes.

Tokens are stored in the `tokens` table. Expired access tokens are refreshed
automatically using the stored refresh token.

## Testing

- Run the test suite with `bin/rails test`. Add system tests as you build
  features that depend on Google OAuth or Gmail interactions.
