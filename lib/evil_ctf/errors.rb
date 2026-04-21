# frozen_string_literal: true
module EvilCTF
  module Errors
    class Error < StandardError; end
    class ConnectionError < Error; end
    class UploadError < Error; end
    class DownloadError < Error; end
    class CryptoError < Error; end
    class ConnectionValidationFailed < Error; end
  end
end
