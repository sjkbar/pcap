package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.NoANDXCommandRequest;
import org.araqne.pcap.smb.response.NoANDXCommandResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0xFF
public class NoANDXCommandParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		NoANDXCommandRequest data = new NoANDXCommandRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		NoANDXCommandResponse data = new NoANDXCommandResponse();
		return data;
	}

	//return STATUS_SMB_BAD_COMMAD;
}
