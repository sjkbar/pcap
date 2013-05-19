package org.araqne.pcap.smb.ntparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.ntreq.NtTransactRenameRequest;
import org.araqne.pcap.smb.ntresp.NtTransactRenameResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;

public class NtTransactRenameParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer) {
		NtTransactRenameRequest transData = new NtTransactRenameRequest();
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer , SmbSession session) {
		NtTransactRenameResponse transData = new NtTransactRenameResponse();
		return transData;
	}

}
