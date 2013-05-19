package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.MoveRequest;
import org.araqne.pcap.smb.response.MoveResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0x2A
public class MoveParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		MoveRequest data = new MoveRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		MoveResponse data = new MoveResponse();
		return data;
	}
	// no longer used
	// return status not implemented
}
