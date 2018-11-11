require "rspec/expectations"

module Lakebed
  module Matchers
    RSpec::Matchers.define :halt do |parameters|
      match do |emu|
        @limit = (parameters && parameters[:after]) || 1000
        emu.begin(@limit)

        @pc = emu.pc

        return emu.mu.mem_read(@pc, 4) == "\x00\x00\x00\x14" # b .
      end
      failure_message do |actual|
        "expected that emulator would halt after #{@limit} instructions"
      end
    end
  end
end
