# frozen_string_literal: true
require_relative 'logger'
module EvilCTF
  # Adapter abstraction for remote shells. Provides a stable `run(cmd)` and `close` API
  # and exposes the underlying WinRM connection when available for advanced operations
  # (e.g., WinRM::FS file manager).
  module ShellAdapter
    # Try to wrap given object into an adapter that responds to `run(cmd)` and `close`.
    def self.wrap(obj)
      return obj if obj.respond_to?(:run) && obj.respond_to?(:close) && obj.respond_to?(:adapter_info) rescue false
      if defined?(WinRM) && obj.is_a?(WinRM::Connection)
        WinRMShellAdapter.new_from_connection(obj)
      elsif defined?(WinRM) && obj.class.to_s =~ /WinRM::Shell/ || (obj.respond_to?(:run) && obj.respond_to?(:close))
        WinRMShellAdapter.new_from_shell(obj)
      else
        GenericAdapter.new(obj)
      end
    end

    class GenericAdapter
      def initialize(obj)
        @obj = obj
      end

      def run(cmd)
        if @obj.respond_to?(:run)
          @obj.run(cmd)
        else
          raise EvilCTF::Errors::ConnectionError, 'Wrapped object does not support run(cmd)'
        end
      end

      def close
        @obj.close if @obj.respond_to?(:close)
      end

      def adapter_info
        { type: :generic }
      end
    end

    # WinRM-specific adapter: can be constructed from a WinRM::Connection or a WinRM shell
    class WinRMShellAdapter < GenericAdapter
      def self.new_from_connection(conn)
        adapter = allocate
        adapter.send(:initialize_from_connection, conn)
        adapter
      end

      def self.new_from_shell(shell)
        adapter = allocate
        adapter.send(:initialize_from_shell, shell)
        adapter
      end

      def initialize_from_connection(conn)
        @conn = conn
        @shell = conn.shell(:powershell)
      end

      def initialize_from_shell(shell)
        @shell = shell
        # try to find connection if available
        @conn = shell.instance_variable_get(:@connection) || shell.instance_variable_get(:@conn) rescue nil
      end

      def run(cmd)
        @shell.run(cmd)
      rescue => e
        raise EvilCTF::Errors::ConnectionError, e.message
      end

      def close
        @shell.close if @shell
        begin; @conn.reset if @conn && @conn.respond_to?(:reset); rescue; end
      end

      def adapter_info
        { type: :winrm, connection: @conn }
      end

      # Return a WinRM::FS file manager if the connection and WinRM::FS are available
      def file_manager
        return nil unless @conn
        return nil unless defined?(WinRM::FS)
        WinRM::FS::FileManager.new(@conn)
      rescue
        nil
      end
    end
  end
end
