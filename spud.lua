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

local pf_pdec = ProtoField.new("Path Declaration",
                               "spud.pdec",
                               ftypes.BOOLEAN,
                               nil,
                               base.DEC,
                               0x10)

local pf_resv = ProtoField.new("Reserved",
                               "spud.resv",
                               ftypes.UINT8,
                               nil,
                               base.HEX,
                               0x08)

local pf_cbor_mt = ProtoField.new("CBOR Major Type",
                                  "spud.cbor_mt",
                                  ftypes.UINT8,
                                  nil,
                                  base.DEC,
                                  0xe0)

local pf_cbor_short_value = ProtoField.new("Value",
                                     "spud.cbor_short",
                                     ftypes.UINT8,
                                     nil,
                                     base.DEC,
                                     0x1F)

local pf_cbor_value = ProtoField.new("Value",
                                     "spud.cbor_value",
                                     ftypes.UINT8,
                                     nil,
                                     base.DEC)

local pf_cbor_bytes = ProtoField.new("Bytes",
                                     "spud.cbor_bytes",
                                     ftypes.STRING)

local pf_cbor_str = ProtoField.new("String",
                                   "spud.cbor_str",
                                   ftypes.STRING)

local pf_cbor_tag = ProtoField.new("Tag",
                                     "spud.cbor_tag",
                                     ftypes.UINT8,
                                     nil,
                                     base.DEC)

spud.fields = { pf_magic, pf_tube, pf_command, pf_adec, pf_pdec, pf_resv,
                pf_cbor_mt, pf_cbor_short_value, pf_cbor_value, pf_cbor_bytes,
                pf_cbor_str, pf_cbor_tag }

local cbor_major_types = {
  "+int", "-int", "bstr", "utf8", "array", "map", "tag", "simple"
}

function cbor(tvbuf,tree)
  -- stupid simple CBOR parser
  local typ = tvbuf:range(0,1)
  local typn = bit32.rshift(bit32.band(typ:uint(), 0xe0), 5)
  local val = bit32.band(typ:uint(), 0x1f)
  local count = 1
  local item = tree:add(pf_cbor_mt, typ):append_text(" "):append_text(cbor_major_types[typn+1])
  local valitem = nil
  if (val < 24) then
    valitem = item:add(pf_cbor_short_value, typ)
  elseif (val == 24) then
    local valr = tvbuf:range(1,1)
    valitem = item:add(pf_cbor_value, valr)
    val = valr:uint()
    count = count+1
  elseif (val == 25) then
    local valr = tvbuf:range(1,2)
    valitem = item:add(pf_cbor_value, valr)
    val = valr:uint()
    count = count+2
  elseif (val == 26) then
    local valr = tvbuf:range(1,4)
    valitem = item:add(pf_cbor_value, valr)
    val = valr:uint()
    count = count+4
  elseif (val == 27) then
    local valr = tvbuf:range(1,8)
    valitem = item:add(pf_cbor_value, valr)
    val = valr:uint64()
    count = count+8
  end

  if typn == 2 then
    -- bstr
    valitem:append_text(" (byte length)")
    item:add(pf_cbor_bytes, tvbuf:range(count, val))
  elseif typn == 3 then
    -- utf8
    valitem:append_text(" (byte length)")
    item:add(pf_cbor_str, tvbuf:range(count, val))
  elseif typn == 4 then
    -- array
    if val == 1 then
      valitem:append_text(" item")
    else
      valitem:append_text(" items")
    end

    for i = 1, val do
      count = count + cbor(tvbuf:range(count, tvbuf:len()-count), item)
    end
  elseif typn == 5 then
    -- map
    if val == 1 then
      valitem:append_text(" key/value pair")
    else
      valitem:append_text(" key/value pairs")
    end

    for i = 1, val do
      count = count + cbor(tvbuf:range(count, tvbuf:len()-count), item)
      count = count + cbor(tvbuf:range(count, tvbuf:len()-count), item)
    end
  elseif typn == 6 then
    count = count + cbor(tvbuf:range(count, tvbuf:len()-count), item)
  elseif typn == 7 then
    if val == 20 then
      valitem:append_text(" False")
    elseif val == 21 then
      valitem:append_text(" True")
    elseif val == 22 then
      valitem:append_text(" Null")
    elseif val == 23 then
      valitem:append_text(" Undefined")
    end
  end
  return count
end

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
    tree:add(pf_resv, flags)
    local count = SPUD_HDR_LEN
    if pktlen > SPUD_HDR_LEN then
      count = count + cbor(tvbuf:range(SPUD_HDR_LEN,pktlen-SPUD_HDR_LEN), tree)
    end

    return count
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
