package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.CreateDirectoryRequest;
import org.araqne.pcap.smb.response.CreateDirectoryResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
// command Code 0x00
public class CreateDirectoryParser implements SmbDataParser{
	byte resWordCount;
	char resByteCount;
	@Override
	public SmbData parseRequest(SmbHeader h,Buffer b , SmbSession session) {
		CreateDirectoryRequest data = new CreateDirectoryRequest();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		data.setBuffferFormat(b.get());
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
		CreateDirectoryResponse data = new CreateDirectoryResponse();
		data.setWordCount(b.get()); // it must 0x00
		data.setByteCount(ByteOrderConverter.swap(b.getShort())); // it must 0x0000
		return data;
	}
}
