package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.SetFsInformationRequest;
import org.araqne.pcap.smb.trans2resp.SetFsInformationResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;

public class SetFsInformationParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer) {
		SetFsInformationRequest transData = new SetFsInformationRequest();
		transData.setFid(parameterBuffer.getShort());
		transData.setInformatoinLevel(parameterBuffer.getShort());
		// TODO Auto-generated method stub
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		SetFsInformationResponse transData = new SetFsInformationResponse();
		// there is no parameters and data
		// TODO Auto-generated method stub
		return transData;
	}

}
