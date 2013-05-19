package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.ReadRawRequest;
import org.araqne.pcap.smb.response.ReadRawResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class ReadRawParser implements SmbDataParser{
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		ReadRawRequest data = new ReadRawRequest();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setOffset(ByteOrderConverter.swap(b.getInt()));
		data.setMaxCountOfBytesToReturn(ByteOrderConverter.swap(b.getShort()));
		data.setMinCountOfBytesToReturn(ByteOrderConverter.swap(b.getShort()));
		data.setTimeout(ByteOrderConverter.swap(b.getInt()));
		data.setReserved(ByteOrderConverter.swap(b.getShort()));
		if(data.getWordCount() == 0x0A)
		{
			data.setOffsetHigh(ByteOrderConverter.swap(b.getInt()));
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		SmbData data = new ReadRawResponse();
		//this packet has no response
		return data;
	}
}
