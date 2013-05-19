package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.trans2req.GetDfsReferralRequest;
import org.araqne.pcap.smb.trans2resp.GetDfsReferalResponse;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class GetDfsReferralParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer) {
		GetDfsReferralRequest transData = new GetDfsReferralRequest();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []referralRequest = new byte[setupBuffer.readableBytes()];
		setupBuffer.gets(referralRequest);
		transData.setReferralRequest(referralRequest);
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		GetDfsReferalResponse transData = new GetDfsReferalResponse();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		byte []referalResponse = new byte[setupBuffer.readableBytes()];
		setupBuffer.gets(referalResponse);
		transData.setReferralReseponse(referalResponse);
		// TODO Auto-generated method stub
		return null;
	}

}
