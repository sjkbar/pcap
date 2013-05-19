package org.araqne.pcap.smb.transparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.transreq.QueryNmpipeInfoRequest;
import org.araqne.pcap.smb.transresp.QueryNmpipeInfoResponse;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class QueryNmpipeInfoParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		QueryNmpipeInfoRequest transData = new QueryNmpipeInfoRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setLevel(ByteOrderConverter.swap(setupBuffer.getShort()));
		
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer paramterBuffer , Buffer dataBuffer , SmbSession session) {
		QueryNmpipeInfoResponse transData = new QueryNmpipeInfoResponse();
		transData.setOutputBufferSize(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setInputBufferSize(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setMaximumInstance(setupBuffer.get());
		transData.setCurrentInstance(setupBuffer.get());
		transData.setPipeNameLength(setupBuffer.get());
		transData.setPipeName(NetBiosNameCodec.readSmbUnicodeName(setupBuffer));
		return transData;
	}
	
	
}
