package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.LogoffANDXRequest;
import org.araqne.pcap.smb.response.LogoffANDXResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class LogoffANDXParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		LogoffANDXRequest data = new LogoffANDXRequest();
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x02){
			data.setAndxCommand(b.get());
			data.setAndxResrved(b.get());
			data.setAndxOffset(ByteOrderConverter.swap(b.getShort()));
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
		LogoffANDXResponse data = new LogoffANDXResponse();
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x02){
			data.setAndXCommand(b.get());
			data.setAndXReserved(b.get());
			data.setAndXOffset(ByteOrderConverter.swap(b.getShort()));
		}
		else{
			data.setMalformed(true);
			b.skip(data.getWordCount()*2);
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
