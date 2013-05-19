package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.CheckDirectoryRequest;
import org.araqne.pcap.smb.response.CheckDirectoryResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class CheckDirectoryParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		CheckDirectoryRequest data = new CheckDirectoryRequest();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		data.setBufferFormat(b.get());
		if(h.isFlag2Unicode()){
			data.setReqDirectoryname(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		else{
			data.setReqDirectoryname(NetBiosNameCodec.readOemName(b));
		}
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h ,Buffer b ,SmbSession session) {
		CheckDirectoryResponse data = new CheckDirectoryResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
		}
		return data;
	}
	

}