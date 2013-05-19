package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.WriteMPXSecondaryRequest;
import org.araqne.pcap.smb.response.WriteMPXSecondaryResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public class WriteMPXSecondaryParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		WriteMPXSecondaryRequest data = new WriteMPXSecondaryRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		WriteMPXSecondaryResponse data = new WriteMPXSecondaryResponse();
		return data;
	}

	//not use
}
