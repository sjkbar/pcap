package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.CallNmpipeRequest;
import org.araqne.pcap.smb.transresp.CallNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class CallNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		CallNmpipeRequest transData = new CallNmpipeRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setPriority(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []writeData = new byte[dataBuffer.readableBytes()];
		dataBuffer.gets(writeData);
		transData.setWriteData(writeData);
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		CallNmpipeResponse transData = new CallNmpipeResponse();
		byte []readData = new byte[setupBuffer.readableBytes()];
		transData.setReadData(readData);
		return transData;
	}
}
