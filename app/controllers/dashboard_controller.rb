require 'google/apis/gmail_v1'
require 'googleauth'

class DashboardController < ApplicationController
  def index
    token = Token.first
    unless token&.access_token.present?
      redirect_to login_path, alert: 'Please authenticate with Google first.'
      return
    end

    ensure_token_freshness(token)
    service = build_gmail_service(token)

    @emails = Rails.cache.fetch(cache_key_for_emails, expires_in: 5.minutes) do
      fetch_latest_emails(service)
    end
  rescue Google::Apis::AuthorizationError
    redirect_to login_path, alert: 'Your session has expired. Please sign in again.'
  rescue Google::Apis::ClientError => e
    @emails = []
    flash.now[:alert] = "Unable to load emails: #{e.message}"
  end

  private

  def ensure_token_freshness(token)
    return unless token.expired?
    Token.access_token # refresh via model logic
    token.reload
    Rails.cache.delete(cache_key_for_emails)
  end

  def build_gmail_service(token)
    authorization = Signet::OAuth2::Client.new(
      client_id: ENV['GOOGLE_CLIENT_ID'],
      client_secret: ENV['GOOGLE_CLIENT_SECRET'],
      token_credential_uri: 'https://oauth2.googleapis.com/token',
      access_token: token.access_token,
      refresh_token: token.refresh_token
    )
    authorization.expires_at = token.expires_at if token.expires_at.present?

    if authorization.expired? && authorization.refresh_token.present?
      authorization.fetch_access_token!
      token.update(
        access_token: authorization.access_token,
        expires_at: authorization.expires_at
      )
    end

    service = Google::Apis::GmailV1::GmailService.new
    service.client_options.application_name = 'Mail Reader'
    service.authorization = authorization
    service
  end

  def extract_header(headers, name)
    headers.find { |h| h.name == name }&.value || 'Unknown'
  end

  def fetch_latest_emails(service)
    response = service.list_user_messages('me', max_results: 10)
    return [] unless response.messages.present?

    response.messages.map do |message_meta|
      message = service.get_user_message(
        'me',
        message_meta.id,
        format: 'metadata',
        metadata_headers: %w[Subject From Date]
      )
      headers = message.payload&.headers || []
      {
        id: message.id,
        subject: extract_header(headers, 'Subject'),
        from: extract_header(headers, 'From'),
        received_at: extract_header(headers, 'Date'),
        snippet: message.snippet
      }
    end
  end

  def cache_key_for_emails
    token = Token.first
    version = token&.updated_at&.to_i || 0
    "dashboard/latest_emails/#{version}"
  end
end
