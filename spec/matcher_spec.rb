require "lakebed"

RSpec.describe "lakebed/matchers" do
  describe "write_to" do
    it "matches values" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # mov w1, #0x456
      # str w1, [x0, 0x1350]
      builder.add_code("\x00\x00\x00\x90\xc1\x8a\x80\x52\x01\x50\x13\xb9")
      builder.add_data(0.chr * 0x400)
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).to write_to(nso + 0x1350, [0x456].pack("L<"))
    end

    it "does not match if the program does not write to the specified address" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # mov w1, #0x456
      # str w1, [x0, 0x1350]
      # b .
      builder.add_code("\x00\x00\x00\x90\xc1\x8a\x80\x52\x01\x50\x13\xb9\x00\x00\x00\x14")
      builder.add_data(0.chr * 0x400)
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).not_to write_to(nso + 0x1358, [0x456].pack("L<"))
    end

    it "does not match if the program does not write the correct value" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # mov w1, #0x456
      # str w1, [x0, 0x1350]
      # b .
      builder.add_code("\x00\x00\x00\x90\xc1\x8a\x80\x52\x01\x50\x13\xb9\x00\x00\x00\x14")
      builder.add_data(0.chr * 0x400)
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).not_to write_to(nso + 0x1350, [0x457].pack("L<"))
    end
  end
  
  describe "read_from" do
    it "matches size == 4" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # ldr w1, [x0, 0x1350]
      builder.add_code("\x00\x00\x00\x90\x01\x50\x53\xb9")
      builder.add_data(0.chr * 0x400)
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).to read_from(nso + 0x1350, 4)
    end

    it "defaults size to 8" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # ldr x1, [x0, 0x1350]
      builder.add_code("\x00\x00\x00\x90\x01\xa8\x49\xf9")
      builder.add_data(0.chr * 0x400)
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).to read_from(nso + 0x1350)
    end

    it "does not match if the program doesn't read the address" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # ldr x1, [x0, 0x1350]
      # b .
      builder.add_code("\x00\x00\x00\x90\x01\xa8\x49\xf9\x00\x00\x00\x14")
      builder.add_data(0.chr * 0x400)
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).not_to read_from(nso + 0x1358) # program writes to 0x1350, not 0x1358
    end
  end

  describe "halt" do
    it "matches if the program enters an infinite loop after 2 instructions" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # b .
      builder.add_code("\x00\x00\x00\x90\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).to halt(:after => 2)
    end

    it "does not match if the program enters an infinite loop after 1 instruction" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # adrp x0, #0
      # b .
      builder.add_code("\x00\x00\x00\x90\x00\x00\x00\x90\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).not_to halt(:after => 1)
    end

    it "has a reasonable default limit" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # adrp x0, #0
      # adrp x0, #0
      # b .
      builder.add_code("\x00\x00\x00\x90\x00\x00\x00\x90\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).to halt
    end
  end

  describe "call_svc" do
    it "matches if the specified svc is called" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # svc 0x1234
      builder.add_code("\x81\x46\x02\xd4")
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).to call_svc(0x1234).and_return(0)
    end

    it "does not match if a different svc is called" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # svc 0x0
      # b .
      builder.add_code("\x01\x00\x00\xd4\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)

      expect(emu).not_to call_svc(0x1234)
    end

    it "matches if registers are correct" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new
      
      # mov w13, #0x5678
      # svc 0x6
      # b .
      builder.add_code("\x0d\xcf\x8a\x52\xc1\x00\x00\xd4\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)
      
      expect(emu).to call_svc(6).with(:x13 => 0x5678).and_return(0)
    end

    it "does not match if registers are not correct" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new
      
      # mov w13, #0x5678
      # svc 0x6
      # b .
      builder.add_code("\x0d\xcf\x8a\x52\xc1\x00\x00\xd4\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)
      
      expect(emu).not_to call_svc(6).with(:x13 => 0x5679).and_return(0)
    end

    it "sets x0 if and_return was specified" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new
      
      # svc 0x6
      # b .
      builder.add_code("\xc1\x00\x00\xd4\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)
      
      expect(emu).to call_svc(6).and_return(0x33bb)
      expect(emu.x0).to eq(0x33bb)
    end

    # does not call the original implementation if and_return was specified
    # calls the original implementation if and_return was not specified
  end
end
