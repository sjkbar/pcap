package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.NtRenameRequest;
import org.araqne.pcap.smb.response.NtRenameResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
//0xA5
public class NtRenameParser implements SmbDataParser{
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		NtRenameRequest data = new NtRenameRequest();
		data.setWordCount(b.get());
		data.setSearchAttributes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort())));
		data.setInformationLevel(b.getShort());
		data.setReserved(ByteOrderConverter.swap(b.getInt()));
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
			data.setNewFileName(NetBiosNameCodec.readOemName(b));
		}
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		NtRenameResponse data = new NtRenameResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	
}
