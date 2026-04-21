# frozen_string_literal: true

require 'yaml'

module EvilCTF
  class ToolRegistry
    Tool = Struct.new(:name, :path, :metadata, keyword_init: true)

    def initialize(root_path:)
      @root_path = root_path
    end

    def scan
      tools_dir = File.join(@root_path, 'tools')
      return [] unless Dir.exist?(tools_dir)

      Dir.glob(File.join(tools_dir, '**', '*')).sort.filter_map do |path|
        next unless File.file?(path)
        next if path.end_with?('.yml', '.yaml')

        Tool.new(
          name: File.basename(path),
          path: path.sub(/^#{Regexp.escape(@root_path)}\//, ''),
          metadata: metadata_for(path: path)
        )
      end
    end

    def metadata_for(path:)
      sidecar_candidates = ["#{path}.yml", "#{path}.yaml", path.sub(/\.[^.]+$/, '.yml'), path.sub(/\.[^.]+$/, '.yaml')]
      metadata_path = sidecar_candidates.find { |candidate| File.exist?(candidate) }
      return default_metadata(path: path) unless metadata_path

      data = YAML.load_file(metadata_path)
      data.is_a?(Hash) ? data : default_metadata(path: path)
    rescue StandardError
      default_metadata(path: path)
    end

    def build_invocation(tool_name:, arguments: {})
      tool = scan.find { |item| item.name == tool_name }
      return nil unless tool

      required_args = Array(tool.metadata['required_args'])
      missing = required_args.reject { |key| arguments.key?(key.to_sym) || arguments.key?(key.to_s) }
      return { error: "missing required arguments: #{missing.join(', ')}" } unless missing.empty?

      command = case File.extname(tool.path).downcase
                when '.ps1', '.psm1'
                  "powershell -ExecutionPolicy Bypass -File \"#{tool.path.gsub('/', '\\\\')}\""
                when '.exe', '.bat', '.cmd'
                  "\"#{tool.path.gsub('/', '\\\\')}\""
                else
                  tool.path
                end

      suffix = arguments.map { |k, v| "-#{k} #{v}" }.join(' ')
      { command: [command, suffix].reject(&:empty?).join(' '), tool: tool }
    end

    private

    def default_metadata(path:)
      {
        'required_args' => [],
        'description' => "Tool entry for #{File.basename(path)}"
      }
    end
  end
end
