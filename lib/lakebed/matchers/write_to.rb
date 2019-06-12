require "rspec/expectations"

module Lakebed
  module Matchers
    RSpec::Matchers.define :write_to do |a, b, c=nil|
      match do |subject|
        if subject.is_a? Proc then
          @emu = a
          @address = b
          match = c
        else
          @emu = subject
          @address = a
          match = b
        end

        if match.is_a? String then
          @match_size = match.bytesize
          @match_content = match
        elsif match.is_a? Integer then
          @match_size = match
          @match_content = nil
        else
          raise "invalid parameter"
        end

        @written_size = nil
        @written_value = nil
        proc = Proc.new do |uc, access, address, size, value|
          @written_size = size
          case size
          when 1
            @written_value = [value].pack("C")
          when 2
            @written_value = [value].pack("S<")
          when 4
            @written_value = [value].pack("L<")
          when 8
            @written_value = [value].pack("Q<")
          else
            if @match_content then
              raise "unhandled size: #{size}"
            end
          end
          @emu.mu.emu_stop
        end # keep this in a local variable since unicorn gem doesn't do GC right...
        
        hook = @emu.mu.hook_add(UnicornEngine::UC_HOOK_MEM_WRITE, proc, nil, @address, @address + @match_size - 1)
        if subject.is_a? Proc then
          subject.call
        else
          @emu.begin
        end

        @emu.mu.hook_del(hook)

        @pc = @emu.pc

        if @match_content then
          return @written_value == @match_content
        else
          return @written_size == @match_size
        end
      end

      supports_block_expectations
      
      failure_message do |actual|
        first_line = "expected that emulator would write #{@match_content.unpack("H*").first} to 0x#{@address.to_s(16)}"
        if @written_value then
          second_line = "wrote #{@written_value.unpack("H*").first} instead (pc #{@pc.to_s(16)})"
        else
          second_line = "stuck at #{@pc.to_s(16)}"
        end
        return first_line + "\n     " + second_line
      end
    end
  end
end
