package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.SessionSetupRequest;
import org.araqne.pcap.smb.trans2resp.SessionSetupResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;

public class SessionSetupParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer) {
		SessionSetupRequest transData = new SessionSetupRequest();
		// TODO Auto-generated method stub
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		SessionSetupResponse transData = new SessionSetupResponse();
		// TODO Auto-generated method stub
		return transData;
	}

}
