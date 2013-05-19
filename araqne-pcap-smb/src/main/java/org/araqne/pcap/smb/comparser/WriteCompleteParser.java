package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.WriteCompleteRequest;
import org.araqne.pcap.smb.response.WriteCompleteResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
//0x20
import org.araqne.pcap.util.Buffer;
public class WriteCompleteParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		SmbData data = new WriteCompleteRequest(); 
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		SmbData data = new WriteCompleteResponse();
		return data;
	}
 //SmbComWriteRaw final response
}
