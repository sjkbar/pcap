package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.CloseAndTreeDiscRequest;
import org.araqne.pcap.smb.response.CloseAndTreeDiscResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
// 0x31
public class CloseAndTreeDiscParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h ,Buffer b , SmbSession session) {
		CloseAndTreeDiscRequest data = new CloseAndTreeDiscRequest();
		// Not Implement ERROR
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h ,Buffer b, SmbSession session) {
		CloseAndTreeDiscResponse data = new CloseAndTreeDiscResponse();
		// Not Implement ERROR
		return data;
	}

	//no use
	// return STATUS_NOT_IMPLEMETED
}
