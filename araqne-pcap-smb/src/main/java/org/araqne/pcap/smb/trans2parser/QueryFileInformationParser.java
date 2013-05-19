package org.araqne.pcap.smb.trans2parser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.QueryFileInformationRequest;
import org.araqne.pcap.smb.trans2resp.QueryFileInformationResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class QueryFileInformationParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		QueryFileInformationRequest transData = new QueryFileInformationRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setFid(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setInformationLevel(ByteOrderConverter.swap(parameterBuffer.getShort()));//2.2.2.3.3
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		QueryFileInformationResponse transData = new QueryFileInformationResponse();
		transData.setEaErrorOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
		//data belong to informationlevel
		return transData;
	}

}
