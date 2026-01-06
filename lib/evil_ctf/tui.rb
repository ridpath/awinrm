# Minimal TTY Toolkit-safe TUI prototype for EvilCTF
# This file is intentionally resilient if TTY gems are not installed.

module EvilCTF
  class TUI
    def self.start(shell = nil, options = {})
      begin
        require 'tty-prompt'
        require 'tty-table'
      rescue LoadError
        puts "TTY gems not installed. Install tty-prompt and tty-table to enable the TUI."
        return
      end

      prompt = TTY::Prompt.new

      # Simple placeholder menu
      loop do
        choice = prompt.select('EvilCTF TUI Prototype', ['Show Banner', 'Run Flag Scan', 'Exit'])
        case choice
        when 'Show Banner'
          puts "(TUI) Banner would render here"
        when 'Run Flag Scan'
          puts "(TUI) Flag scan would run and show results here"
        when 'Exit'
          break
        end
      end
    end
  end
end
