require 'googleauth'

class Token < ApplicationRecord
  def self.access_token
    token = first_or_create
    if token.expired?
      refresh_access_token(token)
    end
    token.access_token
  end

  def expired?
    expires_at.blank? || expires_at < Time.current
  end

  private

  def self.refresh_access_token(token)
    return token.access_token if token.refresh_token.blank?

    client = Signet::OAuth2::Client.new(
      client_id: ENV['GOOGLE_CLIENT_ID'],
      client_secret: ENV['GOOGLE_CLIENT_SECRET'],
      token_credential_uri: 'https://oauth2.googleapis.com/token',
      refresh_token: token.refresh_token
    )

    begin
      client.fetch_access_token!
    rescue Signet::AuthorizationError
      return token.access_token
    end

    token.update(
      access_token: client.access_token,
      expires_at: client.expires_at || Time.current + client.expires_in.to_i.seconds
    )
    token.access_token
  end
end