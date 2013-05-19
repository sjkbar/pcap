package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.RenameRequest;
import org.araqne.pcap.smb.response.RenameResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class RenameParser implements SmbDataParser{
	
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		RenameRequest data = new RenameRequest();
		data.setWordCount(b.get());
		data.setSearchAttributes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort())&0xffff));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		data.setBufferFormat1(b.get());
		if(h.isFlag2Unicode()){
			data.setOldFileName(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		else{
			data.setOldFileName(NetBiosNameCodec.readOemName(b));
		}
		data.setBufferFormat2(b.get());
		if(h.isFlag2Unicode()){
			data.setNewFileName(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		else{
			data.setNewFileName(NetBiosNameCodec.readSmbUnicodeName(b));
		}
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		RenameResponse data = new RenameResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	
}
