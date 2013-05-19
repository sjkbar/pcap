package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.QueryInfoRequest;
import org.araqne.pcap.smb.response.QueryInfoResponse;
import org.araqne.pcap.smb.rr.FileAttributes;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
// 0x08
public class QueryInfoParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		QueryInfoRequest data = new QueryInfoRequest();
		data.setWordCount(b.get());
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
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		QueryInfoResponse data = new QueryInfoResponse();
		byte[]reserved = new byte[10];
		data.setWordCount(b.get());
		data.setFileAttributes( FileAttributes.parse(ByteOrderConverter.swap(b.getShort())&0xffff));
		data.setLastWriteTime(ByteOrderConverter.swap(b.getInt()));
		data.setFileSize(ByteOrderConverter.swap(b.getInt()));
		b.gets(reserved);
		data.setReserved(reserved);
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
