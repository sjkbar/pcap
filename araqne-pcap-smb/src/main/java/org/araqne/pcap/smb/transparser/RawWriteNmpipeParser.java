package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.RawWriteNmpipeRequest;
import org.araqne.pcap.smb.transresp.RawWriteNmpipeResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class RawWriteNmpipeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		RawWriteNmpipeRequest transData = new RawWriteNmpipeRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []writeData = new byte[setupBuffer.readableBytes()];
		transData.setWriteData(writeData);
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		RawWriteNmpipeResponse transData = new RawWriteNmpipeResponse();
		if(parameterBuffer.readableBytes() ==0x02){
			transData.setBytesWritten(ByteOrderConverter.swap(parameterBuffer.getShort()));
		}
		return transData;
	}

	
}
