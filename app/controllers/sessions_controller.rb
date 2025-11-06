class SessionsController < ApplicationController
  def login
    redirect_to '/auth/google_oauth2'
  end

  def create
    auth = request.env['omniauth.auth']
    token = Token.first_or_create
    expires_in = auth.credentials.expires_in
    update_attrs = {
      access_token: auth.credentials.token,
      expires_at: expires_in ? Time.now + expires_in.seconds : nil
    }
    refresh_token = auth.credentials.refresh_token
    update_attrs[:refresh_token] = refresh_token if refresh_token.present?
    token.update(update_attrs)
    redirect_to dashboard_path, notice: 'Authenticated successfully!'
  end
end