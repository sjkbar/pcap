package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.NewFileSizeRequest;
import org.araqne.pcap.smb.response.NewFileSizeResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public class NewFileSizeParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		NewFileSizeRequest data = new NewFileSizeRequest();
		// not implement ERROR
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		NewFileSizeResponse data = new NewFileSizeResponse();
		// not implememt ERROR
		return data;
	}

	//// not implemented
	//  return STATUS_NOT_IMPLEMENTED
}
