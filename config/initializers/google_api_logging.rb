require 'logger'

Google::Apis.logger = Logger.new($stdout)
Google::Apis.logger.level = Logger::WARN
Google::Apis::ClientOptions.default.log_http_requests = false