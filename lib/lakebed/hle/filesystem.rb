require_relative "hle_service.rb"

module Lakebed
  module HLE
    class FilesystemServer < HLEService
      def register_services
        register("fsp-srv") do
          IFileSystemProxy.new
        end
      end

      class IFileSystemProxy < CMIF::Object
        command(
          1, # SetCurrentProcess
          CMIF::In::Pid.new,
          CMIF::In::RawData.new(8, "Q<")) do |pid, _|
        end

        command(
          110, # OpenContentStorageFileSystem
          CMIF::In::RawData.new(4, "L<"),
          CMIF::Out::Object.new) do |content_storage_id|
          puts "opening CSFS #{content_storage_id}"
          IFileSystem.new
        end
      end

      class IFileSystem < CMIF::Object
        
      end
    end
  end
end
