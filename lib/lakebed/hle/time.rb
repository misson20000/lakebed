require_relative "hle_service.rb"

module Lakebed
  module HLE
    class TimeServer < HLEService
      def initialize(kernel)
        super(kernel)
        
        @shmem = Lakebed::Memory::MemoryResource.new((0.chr * 0x1000).force_encoding("ASCII-8BIT"), "time shmem")
      end

      attr_reader :shmem
      
      def register_services
        register("time:u") do
          IStaticService.new(self)
        end
      end
      
      class IStaticService < CMIF::Object
        def initialize(ts)
          @ts = ts
        end

        command(
          0, :GetStandardUserSystemClock,
          CMIF::Out::Object.new) do
          ISystemClock.new
        end
        
        command(
          1, :GetStandardNetworkSystemClock,
          CMIF::Out::Object.new) do
          ISystemClock.new
        end
        
        command(
          2, :GetStandardSteadyClock,
          CMIF::Out::Object.new) do
          ISystemClock.new
        end
        
        command(
          3, :GetTimeZoneService,
          CMIF::Out::Object.new) do
          ITimeZoneService.new
        end

        command(
          20, :GetSharedMemoryNativeHandle,
          CMIF::Out::Handle.new(:copy)) do
          @ts.shmem
        end
      end

      class ISystemClock < CMIF::Object
      end
      
      class ITimeZoneService < CMIF::Object
      end
    end
  end
end
