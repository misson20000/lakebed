module Lakebed
  class Environment
    def initialize(target_firmware, ams, master_key_rev)
      @target_firmware = target_firmware
      @ams_release_major = ams[0]
      @ams_release_minor = ams[1]
      @ams_release_micro = ams[2]
      @master_key_rev = master_key_rev
    end

    attr_reader :target_firmware
    attr_reader :ams_release_major
    attr_reader :ams_release_minor
    attr_reader :ams_release_micro
    attr_reader :master_key_rev
  end
end
