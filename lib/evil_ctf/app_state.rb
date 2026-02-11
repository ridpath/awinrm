require 'thread'

module EvilCTF
  class AppState
    def self.instance
      @instance ||= new
    end

    def initialize
      @mutex = Mutex.new
      @sessions = []
      @active_session = nil
      @running_tasks = {}
      @alerts = []
      @last_scan_time = nil
      @mode = :NORMAL
      @results_buffer = []
      @stream_buffer = []
      @uploads = {}
      @cli_input = ''
      @cli_history = []
      @menu_open = nil
    end

    attr_reader :mutex

    def sessions
      @mutex.synchronize { @sessions.dup }
    end

    def add_session(s)
      @mutex.synchronize { @sessions << s }
    end

    def active_session
      @mutex.synchronize { @active_session }
    end

    def set_active_session(s)
      @mutex.synchronize { @active_session = s }
    end

    def running_tasks
      @mutex.synchronize { @running_tasks.dup }
    end

    def add_task(id, info)
      @mutex.synchronize { @running_tasks[id] = info }
    end

    def remove_task(id)
      @mutex.synchronize { @running_tasks.delete(id) }
    end

    def alerts
      @mutex.synchronize { @alerts.dup }
    end

    def push_alert(a)
      @mutex.synchronize { @alerts << a }
    end

    def last_scan_time
      @mutex.synchronize { @last_scan_time }
    end

    def set_last_scan_time(t)
      @mutex.synchronize { @last_scan_time = t }
    end

    def mode
      @mutex.synchronize { @mode }
    end

    def set_mode(m)
      @mutex.synchronize { @mode = m }
    end

    # CLI input / history helpers for interactive pane
    def cli_input
      @mutex.synchronize { @cli_input.dup }
    end

    def set_cli_input(val)
      @mutex.synchronize { @cli_input = val.to_s }
    end

    def append_cli_history(val)
      @mutex.synchronize do
        @cli_history << val.to_s
        @cli_history.shift while @cli_history.size > 200
      end
    end

    def cli_history_snapshot
      @mutex.synchronize { @cli_history.dup }
    end

    def menu_open
      @mutex.synchronize { @menu_open }
    end

    def set_menu_open(sym)
      @mutex.synchronize { @menu_open = sym }
    end

    def append_result(line)
      @mutex.synchronize do
        @results_buffer << line.to_s
        @results_buffer.shift while @results_buffer.size > 1000
      end
    end

    def results_snapshot
      @mutex.synchronize { @results_buffer.dup }
    end

    def append_stream(line)
      @mutex.synchronize do
        @stream_buffer << line.to_s
        @stream_buffer.shift while @stream_buffer.size > 300
      end
    end

    def stream_snapshot
      @mutex.synchronize { @stream_buffer.dup }
    end

    def uploads
      @mutex.synchronize { @uploads.dup }
    end

    def set_upload(id, info)
      @mutex.synchronize { @uploads[id] = info }
    end

    def clear_upload(id)
      @mutex.synchronize { @uploads.delete(id) }
    end
  end
end
