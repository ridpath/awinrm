# frozen_string_literal: true

require_relative 'execution'
require_relative 'engine_audit'

module EvilCTF
  class SessionHeartbeat
    def initialize(shell:, on_update: nil, interval_seconds: 30)
      @shell = shell
      @on_update = on_update
      @interval_seconds = interval_seconds.to_i
      @running = false
      @thread = nil
    end

    def start
      return if @running

      @running = true
      @thread = Thread.new do
        while @running
          begin
            result = EvilCTF::Execution.run(@shell, '$env:COMPUTERNAME', timeout: 8)
            payload = {
              connected: !!result&.ok,
              hostname: result&.output.to_s.strip,
              checked_at: Time.now
            }
            @on_update&.call(payload)
          rescue StandardError => e
            EvilCTF::EngineAudit.error(message: 'heartbeat poll failed', error: e, source: 'session_heartbeat')
            @on_update&.call({ connected: false, hostname: nil, checked_at: Time.now })
          end
          sleep(@interval_seconds)
        end
      end
    end

    def stop
      return unless @running

      @running = false
      @thread&.join(2)
      @thread = nil
    end
  end
end
