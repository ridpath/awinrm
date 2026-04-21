# frozen_string_literal: true

require 'thread'
require_relative 'execution'
require_relative 'sanitizer'
require_relative 'engine_audit'

module EvilCTF
  class AsyncWorker
    Job = Struct.new(:priority, :name, :shell, :command, :logger, :on_complete, :block, keyword_init: true)

    def initialize
      @queue = Queue.new
      @priority_buffer = []
      @mutex = Mutex.new
      @running = true
      @thread = Thread.new { run_loop }
    end

    def enqueue(priority:, name:, shell:, command:, logger: nil, on_complete: nil)
      sanitized = EvilCTF::Sanitizer.sanitize_command(command: command)
      job = Job.new(
        priority: priority.to_i,
        name: name.to_s,
        shell: shell,
        command: sanitized,
        logger: logger,
        on_complete: on_complete
      )
      @mutex.synchronize do
        @priority_buffer << job
        @priority_buffer.sort_by! { |item| item.priority }
        @priority_buffer.each { |item| @queue << item }
        @priority_buffer.clear
      end
      true
    rescue StandardError => e
      EvilCTF::EngineAudit.error(message: 'failed to enqueue async job', error: e, source: 'async_worker')
      false
    end

    def enqueue_block(priority:, name:, logger: nil, on_complete: nil, &block)
      raise ArgumentError, 'block is required' unless block_given?

      job = Job.new(
        priority: priority.to_i,
        name: name.to_s,
        shell: nil,
        command: nil,
        logger: logger,
        on_complete: on_complete,
        block: block
      )
      @mutex.synchronize do
        @priority_buffer << job
        @priority_buffer.sort_by! { |item| item.priority }
        @priority_buffer.each { |item| @queue << item }
        @priority_buffer.clear
      end
      true
    rescue StandardError => e
      EvilCTF::EngineAudit.error(message: 'failed to enqueue async block job', error: e, source: 'async_worker')
      false
    end

    def shutdown
      @running = false
      @queue << :shutdown
      @thread.join(2)
    end

    private

    def run_loop
      while @running
        item = @queue.pop
        break if item == :shutdown
        process(job: item)
      end
    rescue StandardError => e
      EvilCTF::EngineAudit.error(message: 'async worker loop crashed', error: e, source: 'async_worker')
    end

    def process(job:)
      if job.block
        block_result = job.block.call
        job.on_complete&.call(block_result)
        return
      end

      result = EvilCTF::Execution.run(job.shell, job.command, timeout: 300)
      output = result&.output.to_s
      job.logger&.info("[AsyncWorker] #{job.name}: #{output}") unless output.empty?
      unless result&.ok
        EvilCTF::EngineAudit.error(
          message: "async job failed: #{job.name} exit=#{result&.exitcode}",
          source: 'async_worker'
        )
      end
      job.on_complete&.call(result)
    rescue StandardError => e
      EvilCTF::EngineAudit.error(message: "async job exception: #{job.name}", error: e, source: 'async_worker')
    end
  end
end
