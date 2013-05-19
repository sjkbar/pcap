package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.DeleteRequest;
import org.araqne.pcap.smb.response.DeleteResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class DeleteParser implements SmbDataParser{

	byte resWordCount;// it must 0x00
	char resByteCount; // it must 0x000
	@Override
	public SmbData parseRequest(SmbHeader h,Buffer b , SmbSession session) {
		DeleteRequest data = new DeleteRequest();
		data.setWordCount(b.get());
		data.setSearchAttributes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort())&0xffff));
		data.setByteCount(b.get());
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
		DeleteResponse data = new DeleteResponse();
		 data.setWordCount(b.get());
		 data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
