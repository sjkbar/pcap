package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.QueryPathInformationRequest;
import org.araqne.pcap.smb.trans2resp.QueryPathInformationResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class QueryPathInformationParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		QueryPathInformationRequest transData = new QueryPathInformationRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setInformationLevel(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setReserved(ByteOrderConverter.swap(parameterBuffer.getInt()));
		transData.setFileName(NetBiosNameCodec.readSmbUnicodeName(parameterBuffer));
		//TODO  read GEA List
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		QueryPathInformationResponse transData = new QueryPathInformationResponse();
		transData.setEaErrorOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
		return transData;
	}

}
