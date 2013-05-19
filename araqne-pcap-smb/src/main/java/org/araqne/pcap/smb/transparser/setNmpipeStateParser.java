package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.SetNmpipeStateRequest;
import org.araqne.pcap.smb.transresp.SetNmpipeStateResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class setNmpipeStateParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		SetNmpipeStateRequest transData = new SetNmpipeStateRequest();
		transData.setSubCommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setPipeState(ByteOrderConverter.swap(setupBuffer.getShort()));
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer , SmbSession session) {
		SetNmpipeStateResponse transData = new SetNmpipeStateResponse();
		return transData;
	}

}
