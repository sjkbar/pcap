package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.WriteNmpipeRequest;
import org.araqne.pcap.smb.transresp.WriteNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class WriteNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		WriteNmpipeRequest transData = new WriteNmpipeRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []writeData = new byte[setupBuffer.readableBytes()];
		setupBuffer.gets(writeData);
		transData.setWriteData(writeData);
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		WriteNmpipeResponse transData = new WriteNmpipeResponse();
		transData.setBytesWritten(ByteOrderConverter.swap(setupBuffer.getShort()));
		return transData;
	}

}
