-- declare our protocol
gwlan_proto = Proto("gnunet","Gnunet Layer")
-- create a function to dissect it
local f = gwlan_proto.fields

f.len = ProtoField.uint16 ("gnunet.len", "Gnunet Message Len")
f.type = ProtoField.uint16 ("gnunet.type", "Gnunet Message Type")
-- rhs_proto.fields.sequence = ProtoField.uint16("rhs.sequence","Sequence number")
f.proto = DissectorTable.new("gnunet.proto", "Gnunet Protocoll", FT_UINT16, BASE_DEC)
--gwlan_proto.fields = {f_len, f_type}

function gwlan_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "Gnunet Packet"
	local subtree = tree:add(gwlan_proto, buffer(),"Gnunet Data (" .. buffer:len() .. ")")
	local len = buffer(0,2)
	local type = buffer(2,2)
	subtree:add(buffer(0,2), "Len: " .. buffer(0,2):uint())
	subtree:add(buffer(2,2), "Type: " .. buffer(2,2):uint())
	if (len:uint() > 5) then
		if (len:uint() <= buffer:len()) then
			f.proto:try(type:uint(), buffer(0, len:uint()):tvb(), pinfo, subtree)
		end
		if (len:uint() < buffer:len()) then
			gwlan_proto.dissector(buffer(len:uint(),buffer:len() - len:uint()):tvb(),pinfo,tree)
		end
	end
end

function gwlan_proto.init()
end

-- load the udp.port table
llc_table = DissectorTable.get("llc.dsap")
-- register our protocol to handle llc.dsap 0x1e
llc_table:add(31,gwlan_proto)

fragmentack = Proto("gnunet.fragmentack","Gnunet Fragment Ack")

function fragmentack.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet Fragment ack"
    	tree:add(fragment,buffer(),"Gnunet Data ack")
    	tree:add(buffer(4,4),"fragment_id: " .. buffer(4,4):uint())
    	tree:add(buffer(8,12),"bits: " .. buffer(8,12):uint())
end

fragment = Proto("gnunet.fragment","Gnunet Fragment")

function fragment.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet Fragment"
    	tree:add(fragment,buffer(),"Gnunet Fragment")
    	tree:add(buffer(4,4),"fragment_id: " .. buffer(4,4):uint())
	tree:add(buffer(8,2),"total_size: " .. buffer(8,2):uint())
	tree:add(buffer(10,2),"offset: " .. buffer(10,2):uint())
	tree:add(buffer(12), "Data: " .. buffer(12))
end

hello = Proto("gnunet.hello","Gnunet Hello Message")

function hello.dissector(buffer,pinfo,tree)
    	pinfo.cols.protocol = "Gnunet Hello Message"
    	tree:add(fragment,buffer(),"Gnunet Hello Message")
    	tree:add(buffer(4,4),"reserved: " .. buffer(4,4):uint())
	RsaPublicKeyBinaryEncoded(buffer(8 , buffer:len() -8):tvb(),pinfo, tree)
end


function RsaPublicKeyBinaryEncoded(buffer,pinfo,tree)
    	local subtree = tree:add(gwlan_proto,buffer(),"Gnunet RsaPublicKeyBinaryEncoded(" .. buffer:len() .. ")")
    	subtree:add(buffer(0,2),"len: " .. buffer(0,2):uint())
	subtree:add(buffer(2,2),"sizen: " .. buffer(2,2):uint())
	subtree:add(buffer(4,258),"Pub Key: " .. buffer(4,258))
	subtree:add(buffer(262,2),"pedding: " .. buffer(262,2):uint())
end

f.proto:add(19,fragmentack)
f.proto:add(18,fragment)
f.proto:add(16,hello)
