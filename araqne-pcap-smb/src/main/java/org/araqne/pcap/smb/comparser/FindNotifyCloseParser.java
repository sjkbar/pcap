package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.FindNotifyCloseRequest;
import org.araqne.pcap.smb.response.FindNotifyCloseResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
//0x30
public class FindNotifyCloseParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		FindNotifyCloseRequest data = new FindNotifyCloseRequest();
		return data;
	}

	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		FindNotifyCloseResponse data = new FindNotifyCloseResponse();
		return data;
	}

	// this code have no use
	// if receive this code , must return STATUS_NOT_IMPLEMETED 
}
