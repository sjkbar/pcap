package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.InvalidRequest;
import org.araqne.pcap.smb.response.InvalidResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public class InvalidParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h, Buffer b , SmbSession session) {
		InvalidRequest data = new InvalidRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h, Buffer b ,SmbSession session) {
		InvalidResponse data = new InvalidResponse();
		return data;
	}

}
