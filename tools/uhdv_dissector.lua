-- UHDV (UHD VOD) Protocol Dissector for Wireshark
-- Protocol dissector for vod_stream_tester.py
-- Header: 20 bytes: Magic (4B), Stream ID (4B), Sequence (4B), Send Timestamp (8B)

local uhdv_proto = Proto("uhdv", "UHD VOD Protocol (UHDV)")

-- Protocol Fields
local f_magic     = ProtoField.uint32("uhdv.magic", "Magic", base.HEX)
local f_stream_id = ProtoField.uint32("uhdv.stream_id", "Stream ID", base.HEX_DEC)
local f_seq       = ProtoField.uint32("uhdv.seq", "Sequence Number", base.DEC)
local f_send_ts   = ProtoField.double("uhdv.send_ts", "Send Timestamp (s)")
local f_type      = ProtoField.string("uhdv.type", "Packet Type")
local f_payload   = ProtoField.bytes("uhdv.payload", "Payload Data")

uhdv_proto.fields = { f_magic, f_stream_id, f_seq, f_send_ts, f_type, f_payload }

local VOD_MAGIC = 0x55484456
local VOD_HANDSHAKE_ID = 0xFFFFFFFF
local VOD_HANDSHAKE_PROBE = 0x01
local VOD_HANDSHAKE_ACK   = 0x02

function uhdv_proto.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 20 then return end

    local magic = tvb(0, 4):uint()
    if magic ~= VOD_MAGIC then return end

    pinfo.cols.protocol = "UHDV"

    local stream_id = tvb(4, 4):uint()
    local seq = tvb(8, 4):uint()
    local send_ts = tvb(12, 8):float()

    local ptype_str = "Streaming Data"
    if stream_id == VOD_HANDSHAKE_ID then
        if seq == VOD_HANDSHAKE_PROBE then
            ptype_str = "NAT Handshake Probe"
        elseif seq == VOD_HANDSHAKE_ACK then
            ptype_str = "NAT Handshake ACK"
        else
            ptype_str = "Handshake"
        end
    end

    pinfo.cols.info = string.format("UHDV %s | Seq=%d, StreamID=0x%X", ptype_str, seq, stream_id)

    local subtree = tree:add(uhdv_proto, tvb(0, len), string.format("UHD VOD Protocol (UHDV), %s, Seq: %d", ptype_str, seq))
    subtree:add(f_magic, tvb(0, 4)):append_text(" (ASCII: UHDV)")
    subtree:add(f_stream_id, tvb(4, 4))
    subtree:add(f_seq, tvb(8, 4))
    subtree:add(f_send_ts, tvb(12, 8))
    local type_item = subtree:add(f_type, ptype_str)
    type_item:set_generated()

    if len > 20 then
        subtree:add(f_payload, tvb(20, len - 20))
    end
end

-- Register on UDP port 5005
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(5005, uhdv_proto)

-- Heuristic dissector for dynamic / non-standard ports
local function uhdv_heuristic(tvb, pinfo, tree)
    if tvb:len() >= 20 and tvb(0, 4):uint() == VOD_MAGIC then
        uhdv_proto.dissector(tvb, pinfo, tree)
        return true
    end
    return false
end
uhdv_proto:register_heuristic("udp", uhdv_heuristic)
