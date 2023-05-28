require_relative "hle_service.rb"

module Lakebed
  module HLE
    class SettingsServer < HLEService
      def register_services
        register("set:cal") do
          IFactorySettingsServer.new
        end
      end
      
      class IFactorySettingsServer < CMIF::Object
        command(
          16, :GetSslKey,
          CMIF::Buffer.new(0x16, "key", 0x130)) do |output|
        end
        
        command(
          17, :GetSslCertificate,
          CMIF::Buffer.new(0x16, "key", 0x130)) do |output|
        end
      end
    end
  end
end
