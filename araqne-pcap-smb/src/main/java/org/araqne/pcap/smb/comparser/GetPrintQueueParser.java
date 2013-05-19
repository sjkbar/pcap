package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.GetPrintQueueRequest;
import org.araqne.pcap.smb.response.GetPrintQueueResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0xC3
public class GetPrintQueueParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		GetPrintQueueRequest data = new GetPrintQueueRequest();
		//not implement;
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		GetPrintQueueResponse data = new GetPrintQueueResponse();
		//not implement;
		return data;
	}

	// return STATUS_NOT_IMPLEMENTED;
}
