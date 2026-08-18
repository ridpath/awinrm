# frozen_string_literal: true

module EvilCTF
  # Single source of truth for the remote tool staging directory.
  #
  # The default, C:\Users\Public, is a high-visibility location (every user
  # on the box sees staged tools there). Operators can override it per run
  # with `--staging-path DIR` or a `staging_path:` key in a profile; every
  # remote path (tool registry `recommended_remote`, macro steps, ad-hoc
  # upload destinations, temp logs) derives from this module instead of
  # hardcoding the location.
  module Staging
    DEFAULT_DIR = 'C:\\Users\\Public'

    class << self
      def dir
        @dir || DEFAULT_DIR
      end

      # Accepts drive-letter paths (C:\Temp, d:/staging) and UNC paths
      # (\\server\share). Normalizes to backslashes without a trailing one.
      def dir=(path)
        normalized = normalize(path)
        raise ArgumentError, "invalid staging path: #{path.inspect} (expected e.g. C:\\Temp or \\\\server\\share)" if normalized.nil?

        @dir = normalized
      end

      def reset!
        @dir = nil
      end

      # Join a filename (or relative subpath) onto the staging directory.
      def tool_path(filename)
        "#{dir}\\#{filename}"
      end

      def normalize(path)
        return nil if path.nil? || path.to_s.strip.empty?

        p = path.to_s.strip.tr('/', '\\').sub(/\\+\z/, '')
        p = p.sub(/\A([a-z]):/, &:upcase) # canonicalize drive letter
        return nil unless p.match?(/\A[A-Z]:\\/) || p.match?(/\A[A-Z]:\z/) || p.match?(/\A\\\\/)

        p
      end
    end
  end
end
