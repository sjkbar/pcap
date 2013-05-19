package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.IOCTLSecondaryRequest;
import org.araqne.pcap.smb.response.IOCTLSecondaryResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public class IOCTLSecondaryParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		IOCTLSecondaryRequest data = new IOCTLSecondaryRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		IOCTLSecondaryResponse data = new IOCTLSecondaryResponse();
		return data;
	}
	// reserved;
	// return Status NOT Implemented
}
