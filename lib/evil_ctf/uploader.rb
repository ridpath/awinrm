require_relative 'uploader/client'

module EvilCTF
  module Uploader
    # Backwards-compatible module-level wrappers
    def self.upload_file(local_path, remote_path, shell, **opts)
      client = Client.new(shell)
      client.upload_file(local_path, remote_path, **opts)
    end

    def self.download_file(remote_path, local_path, shell, **opts)
      client = Client.new(shell)
      client.download_file(remote_path, local_path, **opts)
    end
  end
end
