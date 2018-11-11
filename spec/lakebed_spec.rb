require "lakebed"

RSpec.describe Lakebed do
  it "has a version number" do
    expect(Lakebed::VERSION).not_to be nil
  end

  describe Lakebed::Nso do
    describe "#each_segment" do
      it "iterates over segments added by #add_segment" do
        nso = Lakebed::Nso.new
        seg = "abc" + (0.chr * (0x1000 - 3))
        nso.add_segment(seg, 3)
        expect { |b| nso.each_segment(&b) }.to yield_with_args(seg, 3)
      end
    end
  end
  
  describe Lakebed::NsoBuilder do
    describe "#add_code" do
      it "returns an offset" do
        builder = Lakebed::NsoBuilder.new
        expect(builder.add_code("abc")).to be_a(Integer)
      end

      it "increases the offset appropriately" do
        builder = Lakebed::NsoBuilder.new
        expect(builder.add_code("abc")).to eq(0)
        expect(builder.add_code("def")).to eq(3)
      end
    end
    
    describe "#build" do
      it "pads code to page size" do
        builder = Lakebed::NsoBuilder.new
        builder.add_code("abc")
        expect(builder.build.segments.first[0].size).to eq(0x1000)
      end

      it "includes code in an RX segment" do
        builder = Lakebed::NsoBuilder.new
        builder.add_code("abc")
        segment = builder.build.segments.first
        expect(segment[0]).to start_with("abc")
        expect(segment[1]).to eq(5)
      end

      it "does not create a DT_REL tag if #add_rel is not called" do
      end
    end

    describe "#add_rel" do
      it "creates valid DT_REL and DT_RELSZ tags" do
      end

      it "includes the relocation in the DT_REL table" do
      end
    end
  end

  describe Lakebed::Emulator do
    it "should map in a stack" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # sub sp, sp, #0x10
      # str x0, [sp]
      # b .
      builder.add_code("\xff\x43\x00\xd1\xe0\x03\x00\xf9\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)
      emu.begin
    end

    it "should enable NEON" do
      emu = Lakebed::Emulator.new
      builder = Lakebed::NsoBuilder.new

      # dup v0.2d, x8
      # b .
      builder.add_code("\x00\x0d\x08\x4e\x00\x00\x00\x14")
      nso = builder.build

      emu.add_nso(nso)
      emu.begin
    end
  end
end
