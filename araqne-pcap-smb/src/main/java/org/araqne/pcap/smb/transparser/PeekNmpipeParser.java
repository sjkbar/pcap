package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.PeekNmpipeRequest;
import org.araqne.pcap.smb.transresp.PeekNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class PeekNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		PeekNmpipeRequest transData = new PeekNmpipeRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		PeekNmpipeResponse transData = new PeekNmpipeResponse();
		transData.setReadDataAvailable(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setMessageBytesLength(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setNamedPipeState(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []data = new byte[setupBuffer.readableBytes()];
		setupBuffer.gets(data);
		transData.setReadData(data);	
		return transData;
	}
}
