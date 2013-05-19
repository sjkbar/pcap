package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.util.Buffer;


public interface TransParser {
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer DataBuffer);
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer DataBuffer , SmbSession session);
}
