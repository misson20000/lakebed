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

  it "accepts connections to sm:" do
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

    connected = false
    k.named_ports["sm:"].client.connect do |sess|
      connected = true
    end
    k.continue

    expect(connected).to be true
  end

  it "responds to ipc messages" do
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

    session = nil
    k.named_ports["sm:"].client.connect do |sess|
      session = Lakebed::CMIF::ClientSessionObject.new(sess)
    end
    k.continue

    expect(session).not_to be_nil

    session.send_message_sync(
      k,
      Lakebed::CMIF::Message.build_rq(0) do
        pid 0
      end).unpack do
    end

    expect(
      session.send_message_sync(
        k,
        Lakebed::CMIF::Message.build_rq(1) do
          u64("fsp-srv\x00".unpack("Q<")[0])
        end)).to reply_with_error(0xaa01)
  end
end
