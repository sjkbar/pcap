package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.SeekRequest;
import org.araqne.pcap.smb.response.SeekResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SeekParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		SeekRequest data = new SeekRequest();
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x04){
			data.setFid(ByteOrderConverter.swap(b.getShort()));
			data.setMode(ByteOrderConverter.swap(b.getShort()));
			data.setOffset(ByteOrderConverter.swap(b.getInt()));
		}
		else{
			data.setMalformed(true);
			b.skip(data.getWordCount()*2);
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		SeekResponse data = new SeekResponse();
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x02){
			data.setOffset(ByteOrderConverter.swap(b.getInt()));
		}
		else{
			data.setMalformed(true);
			b.skip(data.getWordCount()*2);
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
