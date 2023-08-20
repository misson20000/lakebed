require_relative "hle_service.rb"

module Lakebed
  module HLE
    class LM < HLEService
      def register_services
        register("lm") do
          ILogService.new(self)
        end
      end

      class ILogService < CMIF::Object
        def initialize(lms)
          @lms = lms
        end

        command(
          0, :OpenLogger,
          CMIF::In::Pid.new,
          CMIF::In::RawData.new(8, "Q<"),
          CMIF::Out::Object.new) do |pid, _|
          ILogger.new(@lms, pid)
        end
      end

      class ILogger < CMIF::Object
        def initialize(lms, pid)
          @lms = lms
          @pid = pid
        end

        command(
          0, :Log,
          CMIF::Buffer.new(0x21, "log packet")) do |buffer|
          puts "LM logging"
        end
      end
    end
  end
end
