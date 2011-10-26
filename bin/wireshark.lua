-- declare our protocol
gwlan_proto = Proto("gnunet","Gnunet Layer")
-- create a function to dissect it
local f = gwlan_proto.fields

f.len = ProtoField.uint16 ("gnunet.len", "Gnunet Message Len")
f.type = ProtoField.uint16 ("gnunet.type", "Gnunet Message Type")
-- rhs_proto.fields.sequence = ProtoField.uint16("rhs.sequence","Sequence number")
f_proto = DissectorTable.new("gnunet.proto", "Gnunet Protocoll", FT_UINT16, BASE_DEC)
--gwlan_proto.fields = {f_len, f_type}

function gwlan_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "Gnunet Packet"
	gnunet_packet_disector(buffer,pinfo,tree)
end

function gwlan_proto.init()
end

function gnunet_packet_disector(buffer,pinfo,tree)
	if (buffer:len() > 4) then
		local len = buffer(0,2):uint()
			local type = buffer(2,2):uint()
		if (len <= buffer:len()) then
			local dissect = f_proto:get_dissector(type)
			if dissect ~= nil then
				dissect:call(buffer(0, len):tvb(), pinfo, tree)
			else
				local subtree = tree:add(fragmentack, buffer(),"Gnunet Packet Type: " .. buffer(2,2):uint() .. "(" .. buffer:len() .. ")")
				gnunet_message_header(buffer, pinfo, subtree)
			end
		end
		--if (len < buffer:len()) then
		--	gwlan_proto.dissector(buffer(len, buffer:len() - len):tvb(), pinfo, tree)
		--end
	else
		if (buffer:len() == 4) then
			local subtree = tree:add(fragmentack, buffer(),"Gnunet Packet (" .. buffer:len() .. ")")
			gnunet_message_header(buffer, pinfo, subtree)
		end
	end
end

function gnunet_message_header(buffer, pinfo, tree)
	if (buffer:len() >= 4) then
		local len = buffer(0,2)
		local type = buffer(2,2)
		tree:add(buffer(0,2), "Message Len: " .. buffer(0,2):uint())
		tree:add(buffer(2,2), "Message Type: " .. buffer(2,2):uint())
	end
end

-- load the udp.port table
llc_table = DissectorTable.get("llc.dsap")
-- register our protocol to handle llc.dsap 0x1e
llc_table:add(31,gwlan_proto)

fragmentack = Proto("gnunet.fragmentack","Gnunet Fragment Ack")

function fragmentack.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet Fragment Ack"
	local subtree = tree:add(fragmentack, buffer(),"Gnunet Data ack (" .. buffer:len() .. ")")
	gnunet_message_header(buffer, pinfo, subtree)
	if buffer:len() >= 16 then
	    	subtree:add(buffer(4,4),"Fragment Id: " .. buffer(4,4):uint())
	    	subtree:add(buffer(8,8),"Bits: " .. buffer(8,8))
	end
end

fragment = Proto("gnunet.fragment","Gnunet Fragment")

function fragment.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet Fragment"
	local subtree = tree:add(fragment, buffer(),"Gnunet Fragment (" .. buffer:len() .. ")")
	gnunet_message_header(buffer, pinfo, subtree)
	if buffer:len() >= 13 then
	    	subtree:add(buffer(4,4),"Fragment Id: " .. buffer(4,4):uint())
		subtree:add(buffer(8,2),"Total Size: " .. buffer(8,2):uint())
		subtree:add(buffer(10,2),"Offset: " .. buffer(10,2):uint())
		if buffer(10,2):uint() == 0 then
			if (buffer(8,2):uint() <= buffer:len() - 12) then
				gnunet_packet_disector(buffer(12):tvb(),pinfo,tree)
			end 
		else		
			subtree:add(buffer(12), "Data: " .. buffer(12))
		end
	end
end

hello = Proto("gnunet.hello","Gnunet Hello Message")

function hello.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet Hello Message"
	local subtree = tree:add(hello, buffer(),"Gnunet Hello Message (" .. buffer:len() .. ")")
	gnunet_message_header(buffer, pinfo, subtree)    	
	if buffer:len() > (264 + 8) then
		subtree:add(buffer(4,4),"Reserved: " .. buffer(4,4):uint())
		RsaPublicKeyBinaryEncoded(buffer(8 , 264):tvb(),pinfo, subtree)
	else
		subtree:add(buffer(4), "SIZE WRONG (< 272)")
	end
end

wlan = Proto("gnunet.wlan","Gnunet WLAN Message")

function wlan.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet WLAN Message"
	local subtree = tree:add(wlan, buffer(),"Gnunet WLAN Message (" .. buffer:len() .. ")")
	gnunet_message_header(buffer, pinfo, subtree)
	if buffer:len() > (4 + 4 + 2*64) then
		subtree:add(buffer(4,4),"CRC: " .. buffer(4,4):uint())
		local peer = GNUNET_PeerIdentity(buffer(8,64), pinfo, subtree)
		peer:append_text(" Traget")
		peer = GNUNET_PeerIdentity(buffer(8 + 64,64), pinfo, subtree)
		peer:append_text(" Source")
	else
		subtree:add(buffer(8), "SIZE WRONG (< 4 + 4 + 2*64)")
	end
	if (buffer:len() - (4 + 4 + 2*64) > 0) then
		gnunet_packet_disector(buffer(4 + 4 + 2*64):tvb(),pinfo,tree)
	end 
end

function RsaPublicKeyBinaryEncoded(buffer,pinfo,tree)
    	local subtree = tree:add(gwlan_proto,buffer(),"Gnunet RsaPublicKeyBinaryEncoded(" .. buffer:len() .. ")")
    	subtree:add(buffer(0,2),"Len: " .. buffer(0,2):uint())
	subtree:add(buffer(2,2),"Sizen: " .. buffer(2,2):uint())
	subtree:add(buffer(4,258),"Pub Key: " .. buffer(4,258))
	subtree:add(buffer(262,2),"Padding: " .. buffer(262,2):uint())
end

function GNUNET_PeerIdentity(buffer,pinfo,tree)
    	local subtree = tree:add(gwlan_proto,buffer(),"Gnunet PeerIdentity(" .. buffer:len() .. ")")
    	subtree:add(buffer(0),"hashPubKey: " .. buffer(0))
	return subtree
end

transport_session_keepalive = Proto("gnunet.transport_session_keepalive","Gnunet transport session keepalive")

function transport_session_keepalive.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet transport session keepalive"
	local subtree = tree:add(transport_session_keepalive, buffer(),"Gnunet transport session keepalive (" .. buffer:len() .. ")")
	gnunet_message_header(buffer, pinfo, subtree)
end

f_proto:add(43,wlan)
f_proto:add(39,transport_session_keepalive)
f_proto:add(19,fragmentack)
f_proto:add(18,fragment)
f_proto:add(16,hello)
