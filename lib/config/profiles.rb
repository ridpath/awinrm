# frozen_string_literal: true

require 'yaml'

module EvilCTF
  module Config
    module Profiles
      module_function

      def root_path(default)
        default || File.expand_path('../..', __dir__)
      end

      def load_profiles(root_path: nil)
        root = self.root_path(root_path)
        profile_file = File.join(root, 'config', 'profiles.yaml')
        return {} unless File.exist?(profile_file)

        data = YAML.load_file(profile_file)
        data.is_a?(Hash) ? symbolize_hash(data) : {}
      rescue StandardError
        {}
      end

      def load_profile(name:, root_path: nil)
        return nil if name.to_s.strip.empty?

        root = self.root_path(root_path)
        local_file = File.join(root, 'profiles', "#{name}.yaml")
        if File.exist?(local_file)
          data = YAML.load_file(local_file)
          if data.is_a?(Hash)
            # If the file is wrapped in a top-level profile key, prefer that object.
            nested = data[name.to_s] || data[name.to_sym]
            return symbolize_hash(nested) if nested.is_a?(Hash)
            return symbolize_hash(data)
          end
        end

        profiles = load_profiles(root_path: root)
        profile = profiles[name.to_sym] || profiles[name.to_s.to_sym]
        profile.is_a?(Hash) ? symbolize_hash(profile) : nil
      rescue StandardError
        nil
      end

      def profile_names(root_path: nil)
        root = self.root_path(root_path)
        names = []

        profiles_dir = File.join(root, 'profiles')
        if Dir.exist?(profiles_dir)
          Dir.glob(File.join(profiles_dir, '*.yaml')).sort.each do |path|
            names << File.basename(path, '.yaml')
          end
        end

        names.concat(load_profiles(root_path: root).keys.map(&:to_s))
        names.uniq.sort
      end

      def symbolize_hash(hash)
        hash.each_with_object({}) { |(k, v), out| out[k.to_sym] = v }
      end
    end
  end
end
