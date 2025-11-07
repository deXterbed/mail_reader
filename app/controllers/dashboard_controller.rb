require 'google/apis/gmail_v1'
require 'googleauth'
require 'time'

class DashboardController < ApplicationController
  def index
    token = Token.first
    unless token&.access_token.present?
      redirect_to login_path, alert: 'Please authenticate with Google first.'
      return
    end

    ensure_token_freshness(token)
    service = build_gmail_service(token)

    cache_key = cache_key_for_emails
    cached_emails = Rails.cache.read(cache_key)

    if !cached_emails.nil? && !new_messages_since_last_check?(service, token)
      @emails = cached_emails
    else
      @emails = fetch_latest_emails(service, token)
      Rails.cache.write(cache_key, @emails, expires_in: 5.minutes)
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

  def fetch_latest_emails(service, token)
    response = service.list_user_messages('me', max_results: 10)
    unless response.messages.present?
      profile = service.get_user_profile('me')
      if token && profile&.history_id
        token.update(history_id: profile.history_id)
      end
      return []
    end

    messages = response.messages.map do |message_meta|
      message = service.get_user_message(
        'me',
        message_meta.id,
        format: 'metadata',
        metadata_headers: %w[Subject From Date]
      )
      headers = message.payload&.headers || []
      received_header = extract_header(headers, 'Date')
      received_time = parse_received_at(received_header)
      {
        id: message.id,
        history_id: message.history_id,
        subject: extract_header(headers, 'Subject'),
        from: extract_header(headers, 'From'),
        received_at: received_header,
        received_at_iso: received_time&.iso8601,
        snippet: message.snippet
      }
    end

    latest_history_id = messages.filter_map { |email| email[:history_id]&.to_i }.max

    unless latest_history_id
      profile = service.get_user_profile('me')
      latest_history_id = profile&.history_id&.to_i
    end

    if token && latest_history_id
      token.update(history_id: latest_history_id.to_s)
    end

    messages.map do |email|
      email.except(:history_id).tap do |data|
        data[:received_at_iso] = email[:received_at_iso]
      end
    end
  end

  def cache_key_for_emails
    token = Token.first
    version = token&.updated_at&.to_i || 0
    "dashboard/latest_emails/#{version}"
  end

  def new_messages_since_last_check?(service, token)
    return true if token.nil? || token.history_id.blank?

    response = service.list_user_histories(
      'me',
      start_history_id: token.history_id,
      history_types: ['messageAdded'],
      max_results: 1
    )
    response.history.present?
  rescue Google::Apis::ClientError => e
    return true if e.status_code == 404
    raise
  end

  def parse_received_at(header_value)
    return nil if header_value.blank?
    Time.parse(header_value)
  rescue ArgumentError
    nil
  end
end
