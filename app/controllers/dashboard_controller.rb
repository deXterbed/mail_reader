require 'google/apis/gmail_v1'
require 'googleauth'
require 'time'
require 'base64'
require 'cgi'

class DashboardController < ApplicationController
  def index
    service, token = require_authenticated_service
    return unless service

    cache_key = cache_key_for_emails
    cached_emails = Rails.cache.read(cache_key)

    if params[:refresh] == 'true' || cached_emails.nil?
      @emails = fetch_latest_emails(service, token)
      Rails.cache.write(cache_key, @emails)
      flash.now[:notice] = 'Inbox refreshed.' if params[:refresh] == 'true'
    else
      @emails = cached_emails
    end
  rescue Google::Apis::AuthorizationError
    redirect_to login_path, alert: 'Your session has expired. Please sign in again.'
  rescue Google::Apis::ClientError => e
    @emails = []
    flash.now[:alert] = "Unable to load emails: #{e.message}"
  end

  def show
    service, _token = require_authenticated_service
    return unless service

    message = service.get_user_message('me', params[:id], format: 'full')
    headers = message.payload&.headers || []
    received_header = extract_header(headers, 'Date')
    received_time = parse_received_at(received_header)

    @email = {
      id: message.id,
      subject: extract_header(headers, 'Subject'),
      from: extract_header(headers, 'From'),
      received_at: received_header,
      received_at_iso: received_time&.iso8601,
      snippet: CGI.unescapeHTML(message.snippet.to_s),
      body_html: extract_body_content(message.payload, 'text/html', service, message.id),
      body_text: extract_body_content(message.payload, 'text/plain', service, message.id)
    }
    unless @email[:body_html].present?
      @email[:body_html] = default_html_from_text(@email[:body_text])
    end
    @email[:body_html_data_uri] =
      "data:text/html;charset=utf-8;base64,#{Base64.strict_encode64(@email[:body_html])}" if @email[:body_html].present?
  rescue Google::Apis::AuthorizationError
    redirect_to login_path, alert: 'Your session has expired. Please sign in again.'
  rescue Google::Apis::ClientError => e
    redirect_to dashboard_path, alert: "Unable to load email: #{e.message}"
  end

  private

  def require_authenticated_service
    token = Token.first
    unless token&.access_token.present?
      redirect_to login_path, alert: 'Please authenticate with Google first.'
      return
    end

    ensure_token_freshness(token)
    [build_gmail_service(token), token]
  end

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
    response = service.list_user_messages('me', max_results: 10, label_ids: ['INBOX'])
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
        format: 'full'
      )
      headers = message.payload&.headers || []
      received_header = extract_header(headers, 'Date')
      received_time = parse_received_at(received_header)
      body_preview_html = extract_body_content(
        message.payload,
        'text/html',
        service,
        message.id,
        fetch_attachments: false
      )
      body_preview_text = body_preview_html.present? ? nil : extract_body_content(
        message.payload,
        'text/plain',
        service,
        message.id,
        fetch_attachments: false
      )
      {
        id: message.id,
        history_id: message.history_id,
        subject: extract_header(headers, 'Subject'),
        from: extract_header(headers, 'From'),
        received_at: received_header,
        received_at_iso: received_time&.iso8601,
        snippet: CGI.unescapeHTML(message.snippet.to_s),
        body_preview_html: body_preview_html,
        body_preview_text: body_preview_text
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

  def parse_received_at(header_value)
    return nil if header_value.blank?
    Time.parse(header_value)
  rescue ArgumentError
    nil
  end

  def extract_body_content(payload, mime_type, service, message_id, fetch_attachments: true)
    return nil unless payload

    if payload.mime_type == mime_type
      body_data = payload.body&.data
      encoding = payload_header(payload, 'Content-Transfer-Encoding')
      if fetch_attachments && body_data.blank? && payload.body&.attachment_id.present?
        attachment = service.get_user_message_attachment('me', message_id, payload.body.attachment_id)
        body_data = attachment.data
      end
      return decode_email_body(body_data, encoding) if body_data.present?
    end

    Array(payload.parts).each do |part|
      body = extract_body_content(part, mime_type, service, message_id, fetch_attachments: fetch_attachments)
      return body if body.present?
    end

    nil
  end

  def decode_email_body(data, encoding = nil)
    return nil if data.blank?

    sanitized = data.to_s
    return normalize_encoding(sanitized) unless base64_candidate?(sanitized)

    sanitized = sanitized.delete("\r\n")
    padding = sanitized.length % 4
    sanitized = sanitized.ljust(sanitized.length + (4 - padding) % 4, '=')

    decoded = Base64.urlsafe_decode64(sanitized)
    normalize_encoding(decoded)
  rescue ArgumentError
    encoding&.downcase == 'quoted-printable' ? normalize_encoding(decode_quoted_printable(sanitized)) : normalize_encoding(sanitized)
  end

  def payload_header(payload, name)
    Array(payload.headers).find { |h| h.name.casecmp?(name) }&.value
  end

  def base64_candidate?(data)
    data.present? && data.delete("\r\n=").match?(/\A[-A-Za-z0-9+\/_]+\z/)
  end

  def decode_quoted_printable(data)
    data.gsub("=\r\n", '').gsub(/=([0-9A-Fa-f]{2})/) { Regexp.last_match(1).to_i(16).chr }
  end

  def normalize_encoding(value)
    value.force_encoding('UTF-8')
    value.valid_encoding? ? value : value.encode('UTF-8', invalid: :replace, undef: :replace, replace: '')
  end

  def default_html_from_text(text)
    return nil if text.blank?
    <<~HTML
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8" />
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
              margin: 0;
              padding: 1.5rem;
              background: #0d1117;
              color: #e6edf3;
              line-height: 1.6;
            }
            pre {
              white-space: pre-wrap;
              word-break: break-word;
              font-size: 1rem;
            }
          </style>
        </head>
        <body>
          <pre>#{ERB::Util.html_escape(text)}</pre>
        </body>
      </html>
    HTML
  end
end
