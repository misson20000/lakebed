require "lakebed"

RSpec.describe Lakebed do
  it "reaches startup without crashing" do
    e = Lakebed::Environment.new(
      Lakebed::TargetVersion.new([1,0,0], 450),
      [0, 9, 1],
      0x00)
    k = Lakebed::Kernel.new(e)
    k.strict_svcs = true
    p = Lakebed::Process.new(k)
    File.open("sm.kip") do |f|
      p.add_nso(Lakebed::Files::Kip.from_file(f))
    end
    p.start
    k.continue
  end
end
