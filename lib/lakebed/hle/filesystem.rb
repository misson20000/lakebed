require_relative "hle_service.rb"

module Lakebed
  module HLE
    class FilesystemServer < HLEService
      def register_services
        register("fsp-srv", 32, 0x4000) do
          IFileSystemProxy.new
        end
      end

      class IFileSystemProxy < CMIF::Object
        command(
          1, :SetCurrentProcess,
          CMIF::In::Pid.new,
          CMIF::In::RawData.new(8, "Q<")) do |pid, _|
        end

        command(
          21, :DeleteSaveDataFileSystem,
          CMIF::In::RawData.new(8, "Q<")) do |tid|
          puts "deleting save data filesystem for tid 0x" + tid.to_s(16)
          0
        end

        command(
          52, :OpenSaveDataFileSystemBySystemSaveDataId,
          CMIF::In::RawData.new(1, "C"),
          CMIF::In::RawData.new(0x40),
          CMIF::Out::Object.new) do |save_data_space_id, save_struct|
          puts "opening save data fielsystem by system save id:"
          puts "  save data space id: " + save_data_space_id.to_s
          puts "  save struct: " + save_struct.unpack("H*")[0]

          IFileSystem.new
        end
        
        command(
          110, :OpenContentStorageFileSystem,
          CMIF::In::RawData.new(4, "L<"),
          CMIF::Out::Object.new) do |content_storage_id|
          puts "opening CSFS #{content_storage_id}"
          IFileSystem.new
        end

        command(
          202, :OpenDataStorageByDataId,
          CMIF::In::RawData.new(1, "C", 1, "storage_id"),
          CMIF::In::RawData.new(8, "Q<", 8, "tid"),
          CMIF::Out::Object.new) do |storage, tid|
          puts "opening data storage for title id 0x" + tid.to_s(16)

          case tid
          when 0x0100000000000800
            IStorage.new(File.open("certstore.romfs", "rb"))
          else
            raise "unknown data storage tid: 0x" + tid.to_s(16)
          end
        end
        
        command(
          1003, :DisableAutoSaveDataCreation) do
        end
      end

      class HLEFile
        def initialize(path, content)
          @path = path
          @content = content
        end

        def entry_type
          1
        end

        def resize(new_size)
          if new_size > size then
            @content+= 0.chr * (size - new_size)
          else
            @content = @content.byteslice(0, new_size)
          end
        end
        
        def size
          @content.bytesize
        end
      end

      class HLEDirectory
        def initialize(path)
          @path = path
        end

        def entry_type
          0
        end
      end
      
      class IFileSystem < CMIF::Object
        def initialize
          @paths = {}
        end
        
        command(
          0, :CreateFile,
          CMIF::In::RawData.new(4, "L<", 4, "mode"),
          CMIF::In::RawData.new(8, "Q<", 8, "size"),
          CMIF::Buffer.new(0x19, "path", 0x301)) do |mode, size, path|
          path_string = path.content.unpack("Z769")[0]
          
          puts "creating file of size 0x#{size.to_s(16)} with mode #{mode} at " + path_string

          @paths[path_string] = HLEFile.new(path_string, 0.chr * size)
        end

        command(
          1, :DeleteFile,
          CMIF::Buffer.new(0x19, "path", 0x301)) do |path|
          path_string = path.content.unpack("Z769")[0]

          @paths[path_string] = nil
        end
        
        command(
          2, :CreateDirectory,
          CMIF::Buffer.new(0x19, "path", 0x301)) do |path|
          path_string = path.content.unpack("Z769")[0]

          @paths[path_string] = HLEDirectory.new(path_string)
        end

        command(
          7, :GetEntryType,
          CMIF::Out::RawData.new(4, "L<"),
          CMIF::Buffer.new(0x19, "path", 0x301)) do |path|
          path_string = path.content.unpack("Z769")[0]
          
          if @paths[path_string] then
            @paths[path_string].entry_type
          else
            raise ResultError.new(0x202)
          end
        end
        
        command(
          8, :OpenFile,
          CMIF::In::RawData.new(4, "L<", 4, "mode"),
          CMIF::Buffer.new(0x19, "path", 0x301),
          CMIF::Out::Object.new) do |mode, path|
          path_string = path.content.unpack("Z769")[0]
          
          puts "opening " + path.content.unpack("Z769")[0]

          if @paths[path_string] then
            IFile.new(@paths[path_string])
          else
            puts "couldn't find file"
            raise ResultError.new(0x202)
          end
        end
      end

      class IFile < CMIF::Object
        def initialize(file)
          @file = file
        end

        command(
          1, :Write,
          CMIF::In::RawData.new(4, "L<", 4, "option"),
          CMIF::In::RawData.new(8, "Q<", 8, "offset"),
          CMIF::In::RawData.new(4, "L<", 4, "size")) do |option, offset, size|
        end
        
        command(
          2, :Flush) do
        end

        command(
          3, :SetSize,
          CMIF::In::RawData.new(8, "Q<", 8, "size")) do |size|
          @file.resize(size)
        end
        
        command(
          4, :GetSize,
          CMIF::Out::RawData.new(4, "L<")) do
          @file.size
        end
      end

      class IStorage < CMIF::Object
        def initialize(io)
          @io = io
        end

        command(
          0, :Read,
          CMIF::In::RawData.new(8, "Q<", 8, "offset"),
          CMIF::In::RawData.new(8, "Q<", 8, "length"),
          CMIF::Buffer.new(0x46, "data")) do |offset, length, buffer|
          @io.seek(offset)
          buffer.write(@io.read(length))
        end
      end
    end
  end
end
