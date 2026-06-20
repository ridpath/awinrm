# frozen_string_literal: true

require 'socket'
require 'timeout'
require 'open3'
require 'fileutils'

module EvilCTF
  module Uploader
    # SMB-based file upload for AWINRM.
    #
    # When port 445 is open on the target and smbclient is available on the
    # attacker machine, SMB push is significantly faster than chunked Base64
    # over WinRM — no PowerShell overhead, no encoding tax.
    #
    # Falls back cleanly (returns nil) if smbclient is missing, port 445 is
    # closed, or the SMB connection fails, letting the caller proceed with
    # the standard PowerShell chunked upload path.
    module SmbUpload
      SMB_PORT = 445
      SMB_SHARES = %w[ADMIN$ C$].freeze

      class << self
        # Attempt an SMB push upload. Returns a result hash on success,
        # or nil to signal the caller should fall back.
        def upload(local_path:, remote_path:, ip:, user:, password: nil, hash: nil, domain: '.')
          return nil unless smbclient_available?
          return nil unless port_open?(ip, SMB_PORT)

          # Build the smbclient auth string
          auth_user = domain ? "#{domain}\\#{user}" : user
          auth = if hash
                   # NTLM hash: smbclient expects LM:NT format
                   hash.include?(':') ? hash : "aad3b435b51404eeaad3b435b51404ee:#{hash}"
                   "--pw-nt-hash -U '#{auth_user}'"
                 else
                   "-U '#{auth_user}%#{password}'"
                 end

          # Try ADMIN$ first, then C$
          SMB_SHARES.each do |share|
            result = try_share(share, local_path, remote_path, ip, auth)
            return result if result
          end

          nil
        rescue StandardError => e
          warn "[!] SMB upload error: #{e.class}: #{e.message}"
          nil
        end

        private

        def smbclient_available?
          @smbclient_available ||= begin
            _, status = Open3.capture2e('which', 'smbclient')
            status.success?
          end
        end

        def port_open?(ip, port, timeout: 3)
          Timeout.timeout(timeout) do
            s = TCPSocket.new(ip, port)
            s.close
            true
          end
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Timeout::Error
          false
        end

        def try_share(share, local_path, remote_path, ip, auth)
          # Convert remote Windows path to SMB share-relative path
          rel = smb_relative_path(remote_path, share)

          # For ADMIN$ we can only write to certain paths; limit scope
          if share == 'ADMIN$'
            return nil unless rel

            # Only allow writing to common writable locations under ADMIN$
            allowed_prefixes = %w[system32 sysnative temp].freeze
            prefix = rel.downcase.split(File::SEPARATOR).first
            return nil unless allowed_prefixes.include?(prefix)
          end

          smb_path = "//#{ip}/#{share}/#{rel.tr('\\', '/')}"
          cmd = "smbclient #{smb_path} #{auth} -c 'put \"#{local_path}\" \"#{rel}\"' 2>&1"

          _, status = Open3.capture2e(cmd)

          { ok: true, method: 'smb', share: share, path: rel } if status.success?
        rescue StandardError
          nil
        end

        # Convert a full Windows path (e.g. C:\Users\Public\tool.exe) to
        # a share-relative path (e.g. Users\Public\tool.exe for C$).
        def smb_relative_path(remote_path, share)
          normalized = remote_path.to_s.gsub('/', '\\')

          case share
          when 'C$'
            # Strip drive letter prefix (C:\, c:\) or return nil
            match = normalized.match(/^[A-Za-z]:\\(.*)$/)
            return nil unless match

            match[1]
          when 'ADMIN$'
            # ADMIN$ maps to %SystemRoot% (typically C:\Windows)
            # Strip the Windows dir prefix if present
            normalized.sub(/^[A-Za-z]:\\windows\\/i, '')
          else
            normalized
          end
        end
      end
    end
  end
end
