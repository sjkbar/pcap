package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.QueryFsInformationRequest;
import org.araqne.pcap.smb.trans2resp.QueryFsInformationResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class QueryFsInformationParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		QueryFsInformationRequest transData = new QueryFsInformationRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setInformationLevel(ByteOrderConverter.swap(parameterBuffer.getShort()));
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		QueryFsInformationResponse transData = new QueryFsInformationResponse();
		
		return transData;
	}

}
