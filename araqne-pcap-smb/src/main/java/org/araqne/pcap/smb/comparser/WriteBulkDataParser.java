package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.WriteBulkDataRequest;
import org.araqne.pcap.smb.response.WriteBulkDataResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0xDA
public class WriteBulkDataParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		WriteBulkDataRequest data = new WriteBulkDataRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		WriteBulkDataResponse data = new WriteBulkDataResponse();
		// TODO Auto-generated method stub
		return data;
	}
// return STATUS_NOT_IMPLEMENTED
}
