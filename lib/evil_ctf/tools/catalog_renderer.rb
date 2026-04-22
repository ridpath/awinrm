# frozen_string_literal: true

module EvilCTF
  module Tools
    module CatalogRenderer
      module_function

      def list_available_tools(registry:)
        puts "\n AVAILABLE TOOLS ".ljust(70, '=')
        registry.group_by { |_, v| v[:category] }.each do |cat, tools|
          puts "\n #{cat.upcase}:"
          tools.each do |key, t|
            local_status = File.exist?(File.join('tools', t[:filename])) ? '📁' : '❌'
            puts " [#{local_status}] #{t[:name]} (#{key}) - #{t[:description]}"
          end
        end
        puts "\nCommands:"
        puts ' tools - List available tools'
        puts ' download_missing - Download all missing tools into ./tools'
        puts ' tool <name> - Stage and use a specific tool'
        puts ' tool all - Stage all available tools'
        puts '=' * 70
      end
    end
  end
end
