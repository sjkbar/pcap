package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.DeleteDirectoryRequest;
import org.araqne.pcap.smb.response.DeleteDirectoryResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
// command code 0x01
public class DeleteDirectoryParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		DeleteDirectoryRequest data = new DeleteDirectoryRequest(); 
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		data.setBufferFormat(b.get());
		if(h.isFlag2Unicode()){
			data.setDirectoryName(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		else{
			data.setDirectoryName(NetBiosNameCodec.readOemName(b));
		}
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		DeleteDirectoryResponse data = new DeleteDirectoryResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
