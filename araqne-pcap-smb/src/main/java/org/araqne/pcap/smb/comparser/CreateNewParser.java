package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.CreateNewRequest;
import org.araqne.pcap.smb.response.CreateNewResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class CreateNewParser implements SmbDataParser{
	byte resWordCount;
	@Override
	public SmbData parseRequest(SmbHeader h,Buffer b , SmbSession session) {
		CreateNewRequest data = new  CreateNewRequest();
		data.setWordCount(b.get());
		data.setFileAttributes(FileAttributes.parse(ByteOrderConverter.swap(b.getShort()) &0xffff));
		data.setCreateionTime(ByteOrderConverter.swap(ByteOrderConverter.swap(b.getInt())));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
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
	public SmbData parseResponse(SmbHeader h,Buffer b ,SmbSession session) {
		CreateNewResponse data = new  CreateNewResponse();
		data.setWordCount(b.get());
		if(data.getWordCount() !=0){
			data.setFid(ByteOrderConverter.swap(b.getShort()));
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
