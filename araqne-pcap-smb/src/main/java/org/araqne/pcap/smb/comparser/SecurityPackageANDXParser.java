package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.SecurityPackageANDXRequest;
import org.araqne.pcap.smb.response.SecurityPackageANDXResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
// 0x7E
public class SecurityPackageANDXParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		SecurityPackageANDXRequest data = new SecurityPackageANDXRequest();
		
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		SecurityPackageANDXResponse data = new SecurityPackageANDXResponse();
		
		return data;
	}

	//retrun STATUS NOT IMPLEMENTED
}
