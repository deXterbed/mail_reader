require 'logger'

Google::Apis.logger.level = Logger::WARN
Google::Apis::ClientOptions.default.log_http_requests = false
