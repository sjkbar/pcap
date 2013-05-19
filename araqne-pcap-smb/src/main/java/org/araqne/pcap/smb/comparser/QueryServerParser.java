package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.QueryServerRequest;
import org.araqne.pcap.smb.response.QueryServerResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0x21
public class QueryServerParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		QueryServerRequest data = new QueryServerRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		QueryServerResponse data = new QueryServerResponse();
		return data;
	}

	//reserved not use
}
