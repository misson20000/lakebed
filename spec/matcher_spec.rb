require "lakebed"
require "lakebed/expectations"

RSpec.describe "lakebed/expectations" do
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
end
