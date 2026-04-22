# frozen_string_literal: true

module EvilCTF
  module Session
    class CommandHistory
      def initialize
        @history = []
      end

      def add(cmd)
        @history << cmd
      end

      def show
        @history.each_with_index { |c, i| puts "#{i + 1}: #{c}" }
      end

      def clear
        @history = []
      end

      def history
        @history
      end
    end
  end
end
