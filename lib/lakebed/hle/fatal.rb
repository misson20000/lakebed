require_relative "hle_service.rb"

module Lakebed
  module HLE
    class FatalServer < HLEService
      def register_services
        register("fatal:u") do
          IService.new
        end
      end
      
      class IService < CMIF::Object
      end
    end
  end
end
