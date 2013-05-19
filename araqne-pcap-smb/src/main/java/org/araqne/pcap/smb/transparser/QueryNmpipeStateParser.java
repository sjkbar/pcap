package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.rr.NamedPipeStatus;
import org.araqne.pcap.smb.transreq.QueryNmpipeStateRequest;
import org.araqne.pcap.smb.transresp.QueryNmpipeStateResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class QueryNmpipeStateParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		QueryNmpipeStateRequest transData = new QueryNmpipeStateRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		QueryNmpipeStateResponse transData = new QueryNmpipeStateResponse();
		transData.setStatus(NamedPipeStatus.parse(ByteOrderConverter.swap(setupBuffer.getShort())));
		return transData;
	}
	

}
