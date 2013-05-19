package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.ReadMPXSecondaryRequest;
import org.araqne.pcap.smb.response.ReadMPXSecondaryResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public class ReadMPXSecondaryParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h,Buffer b , SmbSession session) {
		SmbData data = new ReadMPXSecondaryRequest();
		//this packet has no request
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h,Buffer b ,SmbSession session) {
		SmbData data = new ReadMPXSecondaryResponse();
		//this packet has no response
		return data;
	}
// this is not use
}
