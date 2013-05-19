package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.ReadNmpipeRequest;
import org.araqne.pcap.smb.transresp.ReadNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class ReadNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		ReadNmpipeRequest transData = new ReadNmpipeRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		ReadNmpipeResponse transData = new ReadNmpipeResponse();
		byte []readData = new byte[setupBuffer.readableBytes()];
		setupBuffer.gets(readData);
		transData.setReadData(readData);
		return null;
	}

}
