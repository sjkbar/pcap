package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.ProcessExitRequest;
import org.araqne.pcap.smb.response.ProcessExitResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class ProcessExitParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		ProcessExitRequest data = new ProcessExitRequest();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		ProcessExitResponse data = new ProcessExitResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	
}