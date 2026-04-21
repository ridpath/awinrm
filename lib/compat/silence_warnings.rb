# frozen_string_literal: true

# Ruby 4.0 compatibility helper:
# suppresses only known noisy winrm warnings while leaving all other warnings intact.
module EvilCTF
  module Compat
    module SilenceWarnings
      WINRM_OBJECT_ID_WARNING = /winrm\/psrp\/(fragment|message_fragmenter)\.rb:\d+: warning: redefining 'object_id' may cause serious problems/
      WINRM_REDEFINE_WARNING = /winrm\/psrp\/.*warning: redefining 'object_id' may cause serious problems/

      module WarningFilter
        def warn(message, category: nil, **kwargs)
          return if message.to_s.match?(WINRM_OBJECT_ID_WARNING)

          super(message, category: category, **kwargs)
        rescue ArgumentError
          # Older Ruby warning signatures may not support category/kwargs.
          super(message)
        end
      end

      def self.enable!
        return unless defined?(Warning)
        return if @enabled

        if Warning.respond_to?(:ignore)
          Warning.ignore(WINRM_OBJECT_ID_WARNING)
          Warning.ignore(WINRM_REDEFINE_WARNING)
        else
          Warning.singleton_class.prepend(WarningFilter)
        end
        @enabled = true
      end
    end
  end
end

EvilCTF::Compat::SilenceWarnings.enable!