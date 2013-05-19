package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;

public class Ioctl2Parser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		// TODO Auto-generated method stub
		return null;
	}

}
