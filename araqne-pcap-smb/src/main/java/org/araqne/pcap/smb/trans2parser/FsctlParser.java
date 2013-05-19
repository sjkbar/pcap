package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.FsctlRequest;
import org.araqne.pcap.smb.trans2resp.FsctlResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;

public class FsctlParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer) {
		FsctlRequest transData = new FsctlRequest();
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		FsctlResponse transData = new FsctlResponse();
		return transData;
	}

}
