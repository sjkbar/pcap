package org.araqne.pcap.smb.comparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;

public interface SmbDataParser {
	SmbData parseRequest(SmbHeader h, Buffer b ,  SmbSession session);
//	SmbData parseRequest(SmbHeader h, Buffer b);
	SmbData parseResponse(SmbHeader h, Buffer b , SmbSession session);
}
