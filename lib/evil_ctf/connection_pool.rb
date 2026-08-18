# frozen_string_literal: true

require_relative 'connection'

module EvilCTF
  # Process-wide pool of WinRM connections, keyed by endpoint + credentials.
  #
  # Before this, every phase that needed a connection built its own
  # (test_connection validated one and threw it away, run_session built a
  # second, the TUI extra-session flows did the same pair), so a single
  # `--verify` session paid for two full WinRM handshakes. The pool hands
  # the validated connection straight to the session, evicts connections
  # the reconnect path knows are dead, and owns close-at-exit so session
  # connections are no longer leaked (run_session never closed its conn).
  module ConnectionPool
    # LRU cap: multi-host loops and TUI extra sessions must not
    # accumulate unbounded client connections.
    MAX_SIZE = 8

    class << self
      def mutex
        @mutex ||= Mutex.new
      end

      # @return [Hash, nil] cached entry (without the conn) or nil
      def acquire(**params)
        key = key_for(**params)
        mutex.synchronize do
          entry = @entries&.fetch(key, nil)
          if entry
            entry[:last_used] = monotonic
            return entry[:conn]
          end

          evict_lru_if_full
          conn = EvilCTF::Connection.build_full(**params)
          return nil unless conn

          @entries ||= {}
          @entries[key] = { conn: conn, last_used: monotonic, params: params }
          conn
        end
      end

      # Register an already-built (and validated) connection so a later
      # acquire with the same parameters reuses it instead of building.
      def register(conn, **params)
        return nil unless conn

        key = key_for(**params)
        mutex.synchronize do
          @entries ||= {}
          @entries[key] = { conn: conn, last_used: monotonic, params: params }
        end
        conn
      end

      # Remove a connection from the pool and close it.
      def evict(conn)
        return unless conn

        mutex.synchronize do
          @entries ||= {}
          entry = @entries.find { |(_, e)| e[:conn].equal?(conn) }
          if entry
            @entries.delete(entry[0])
            safe_close(conn)
          end
        end
      end

      # Remove without closing (the caller owns the connection's lifetime).
      def detach(conn)
        return unless conn

        mutex.synchronize do
          @entries ||= {}
          entry = @entries.find { |(_, e)| e[:conn].equal?(conn) }
          @entries.delete(entry[0]) if entry
        end
      end

      def close_all
        mutex.synchronize do
          (@entries || {}).each_value { |e| safe_close(e[:conn]) }
          @entries = {}
        end
      end

      def size
        mutex.synchronize { (@entries || {}).size }
      end

      # Identity so specs and the audit log can observe pool behavior.
      def snapshot
        mutex.synchronize do
          (@entries || {}).keys.map { |k| { endpoint: k[:endpoint], user: k[:user], auth: k[:auth] } }
        end
      end

      # Reset for tests.
      def reset!
        mutex.synchronize do
          @entries = {}
        end
      end

      private

      def key_for(**params)
        # Mirror Connection.build_full's endpoint resolution so callers
        # that pass ip:+port: (TUI extra sessions) and callers that pass
        # an explicit endpoint: (CLI / test_connection) key identically.
        endpoint = params[:endpoint] || params[:url]
        if endpoint.nil? && params[:ip]
          port = params[:port] || (params[:ssl] ? 5986 : 5985)
          scheme = params[:ssl] ? 'https' : 'http'
          endpoint = "#{scheme}://#{params[:ip]}:#{port}/wsman"
        end
        auth = if params[:kerberos]
                 :kerberos
               elsif params[:hash]
                 :hash
               else
                 :password
               end
        {
          endpoint: endpoint.to_s,
          user: params[:user].to_s,
          auth: auth,
          ssl: !!params[:ssl],
          transport: params[:transport].to_s
        }
      end

      def evict_lru_if_full
        return unless @entries && @entries.size >= MAX_SIZE

        oldest = @entries.min_by { |(_, e)| e[:last_used] }
        @entries.delete(oldest[0])
        safe_close(oldest[1][:conn])
      end

      def safe_close(conn)
        begin
          conn.close if conn.respond_to?(:close)
        rescue StandardError
          nil
        end
        begin
          conn.reset if conn.respond_to?(:reset)
        rescue StandardError
          nil
        end
      end

      def monotonic
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
