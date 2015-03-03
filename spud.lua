local SPUD_HDR_LEN = 13

local spud = Proto("spud","draft-hildebrand-spud-prototype-02")
local pf_magic = ProtoField.new("Magic number",
                                "spud.magic",
                                ftypes.UINT32,
                                nil,
                                base.HEX)

local pf_tube = ProtoField.new("Tube ID",
                               "spud.tube",
                               ftypes.UINT64,
                               nil,
                               base.HEX)

local pf_command = ProtoField.new("Command",
                                  "spud.cmd",
                                  ftypes.UINT8,
                                  nil,
                                  base.DEC,
                                  0xc0)

local pf_adec = ProtoField.new("Application Declaration",
                               "spud.adec",
                               ftypes.BOOLEAN,
                               nil,
                               base.DEC,
                               0x20)

local pf_pdec = ProtoField.new("Application Declaration",
                               "spud.pdec",
                               ftypes.BOOLEAN,
                               nil,
                               base.DEC,
                               0x10)

spud.fields = { pf_magic, pf_tube, pf_command, pf_adec, pf_pdec }

function spud.dissector(tvbuf,pktinfo,root)
    pktinfo.cols.protocol:set("SPUD")
    local pktlen = tvbuf:reported_length_remaining()
    local tree = root:add(spud, tvbuf:range(0,pktlen))

    if pktlen < SPUD_HDR_LEN then
        print "packet too short"
        return
    end

    tree:add(pf_magic, tvbuf:range(0,4))
    tree:add(pf_tube, tvbuf:range(4,8))

    local flags = tvbuf:range(12,1)
    local cmd_str = ""
    local cmd = bit32.rshift(bit32.band(flags:uint(), 0xc0), 6)
    if cmd == 0 then
        cmd_str = "DATA"
    elseif cmd == 1 then
        cmd_str = "OPEN"
    elseif cmd == 2 then
        cmd_str = "CLOSE"
    elseif cmd == 3 then
        cmd_str = "ACK"
    end
    tree:add(pf_command, flags):append_text(" "):append_text(cmd_str)
    tree:add(pf_adec, flags)
    tree:add(pf_pdec, flags)

    return SPUD_HDR_LEN
end

local function heur_dissect_spud(tvbuf,pktinfo,root)
    if tvbuf:len() < SPUD_HDR_LEN then
        return false
    end
    local tvbr = tvbuf:range(0,4)
    if tvbr:uint() ~= 0xd80000d8 then
        return false
    end

    root:add("Heuristic dissector used"):set_generated()
    spud.dissector(tvbuf,pktinfo,root)
    pktinfo.conversation = spud
    return true
end

spud:register_heuristic("udp",heur_dissect_spud)
