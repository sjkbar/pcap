package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.TransactNmpipeRequest;
import org.araqne.pcap.smb.transresp.TransactNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class TransactNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		TransactNmpipeRequest transData = new TransactNmpipeRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []writeData = new byte[dataBuffer.readableBytes()];
		dataBuffer.gets(writeData);
		transData.setWriteData(writeData);
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		TransactNmpipeResponse transData = new TransactNmpipeResponse();
		byte []readData = new byte[dataBuffer.readableBytes()];
		dataBuffer.gets(readData);
		transData.setReadData(readData);
		return transData;
	}
}
