package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.OpenPrintFileRequest;
import org.araqne.pcap.smb.response.OpenPrintFileResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0xC0
public class OpenPrintFileParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		OpenPrintFileRequest data = new OpenPrintFileRequest();
		data.setWordCount(b.get());
		data.setSetupLength(ByteOrderConverter.swap(b.getShort()));
		data.setMode(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat(b.get());
		if(h.isFlag2Unicode()){
			data.setIdentifier(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		else{
			data.setIdentifier(NetBiosNameCodec.readOemName(b));
		}
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		
		OpenPrintFileResponse data = new OpenPrintFileResponse();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
