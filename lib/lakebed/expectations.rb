require "rspec/expectations"
require_relative "lakebed"

RSpec::Matchers.define :write_to do |address, value|
  match do |emu|
    written_value = nil
    proc = Proc.new do |uc, access, address, size, value|
      case size
      when 1
        written_value = [value].pack("C")
      when 2
        written_value = [value].pack("S<")
      when 4
        written_value = [value].pack("L<")
      when 8
        written_value = [value].pack("Q<")
      else
        raise "unhandled size: #{size}"
      end
      emu.mu.emu_stop
    end # keep this in a local variable since unicorn gem doesn't do GC right...
    hook = emu.mu.hook_add(UnicornEngine::UC_HOOK_MEM_WRITE, proc, nil, address, address + value.size - 1)
    emu.begin
    emu.mu.hook_del(hook)
    
    return written_value == value
  end
  failure_message do |actual|
    "expected that emulator would write #{value.unpack("H*").first} to 0x#{address.to_s(16)}"
  end
end

RSpec::Matchers.define :read_from do |address, match_size|
  if match_size == nil then
    match_size = 8
  end
  match do |emu|
    @read_size = nil
    proc = Proc.new do |uc, access, address, size, value|
      @read_size = size
      emu.mu.emu_stop
    end # keep this in a local variable since unicorn gem doesn't do GC right...

    hook = emu.mu.hook_add(UnicornEngine::UC_HOOK_MEM_READ, proc, nil, address, address + match_size - 1)
    emu.begin
    emu.mu.hook_del(hook)

    return @read_size == match_size
  end
  failure_message do |actual|
    first_line = "expected that emulator would read 0x#{match_size.to_s(16)} bytes from 0x#{address.to_s(16)}"
    if @read_size then
      second_line = "     read: #{@read_value.unpack("H*").first}"
    else
      second_line = "     watchpoint was not hit"
    end
    return first_line + "\n" + second_line
  end
end
