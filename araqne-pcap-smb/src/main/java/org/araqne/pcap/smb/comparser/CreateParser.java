package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.CreateRequest;
import org.araqne.pcap.smb.response.CreateResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class CreateParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h,Buffer b , SmbSession session) {
		CreateRequest data = new CreateRequest();
		data.setWordCount(b.get());
		data.setFileattr(FileAttributes.parse(ByteOrderConverter.swap(ByteOrderConverter.swap(b.getShort())) & 0xffff));
		data.setCreateTime(ByteOrderConverter.swap(b.getInt()));
		data.setByteCount(ByteOrderConverter.swap(ByteOrderConverter.swap(b.getShort())));
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
		CreateResponse data = new CreateResponse();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(ByteOrderConverter.swap(ByteOrderConverter.swap(b.getShort()))));
		data.setByteCount(ByteOrderConverter.swap(ByteOrderConverter.swap(ByteOrderConverter.swap(b.getShort()))));
		return data;
	}
	

}
