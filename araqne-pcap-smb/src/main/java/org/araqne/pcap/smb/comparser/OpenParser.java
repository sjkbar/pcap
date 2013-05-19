package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.OpenRequest;
import org.araqne.pcap.smb.response.OpenResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class OpenParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		OpenRequest data = new OpenRequest();
		data.setWordCount(b.get());
		data.setAccessMode(ByteOrderConverter.swap(b.getShort()));
		data.setSearchAttributes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort())&0xffff));
		data.setbyteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat(b.get());
		if(h.isFlag2Unicode()){
			data.setFileName(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		else{
			data.setFileName(NetBiosNameCodec.readOemName(b));
		}
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		OpenResponse data = new OpenResponse();
		data.setWordCount(b.get());
		if(data.getWordCount() !=0){
			data.setFid(ByteOrderConverter.swap(b.getShort()));
			data.setFileAttrs(FileAttributes.parse(ByteOrderConverter.swap(b.getShort()) & 0xffff));
		}
		data.setByteCount(ByteOrderConverter.swap((b.getShort())));
		return data;
	}
	
}