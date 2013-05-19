package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.ReadBulkRequest;
import org.araqne.pcap.smb.response.ReadBulkResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0xD8
public class ReadBulkParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		ReadBulkRequest data = new ReadBulkRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		ReadBulkResponse data = new ReadBulkResponse();
		return data;
	}

	//return STATUS_NOT_IMPLEMENTED;
}
