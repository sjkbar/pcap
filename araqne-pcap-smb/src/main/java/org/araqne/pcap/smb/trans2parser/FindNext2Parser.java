package org.araqne.pcap.smb.trans2parser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.FindInfoLevelMapper;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.smb.request.Transaction2Request;
import org.araqne.pcap.smb.rr.FindInformationLevel;
import org.araqne.pcap.smb.trans2req.FindNext2Request;
import org.araqne.pcap.smb.trans2resp.FindNext2Response;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class FindNext2Parser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer  , Buffer parameterBuffer , Buffer dataBuffer) {
		FindNext2Request transData = new FindNext2Request();
		transData.setSubcommand(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setSid(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setSearchCount(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setInformationLevel(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setResumekey(ByteOrderConverter.swap(parameterBuffer.getInt()));
		transData.setFlags(ByteOrderConverter.swap(parameterBuffer.getShort()));
		transData.setFileName(NetBiosNameCodec.readSmbUnicodeName(parameterBuffer));
//		System.out.println(transData.getFileName());
		// read GEA List
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer , Buffer dataBuffer , SmbSession session) {
		FindNext2Response transData = new FindNext2Response();
		FindInfoLevelMapper mapper = new FindInfoLevelMapper();
		TransStruct []struct;
		if(parameterBuffer.readableBytes() !=0){
			transData.setSearchCount(ByteOrderConverter.swap(parameterBuffer.getShort()));
			transData.setEndOfSearch(ByteOrderConverter.swap(parameterBuffer.getShort()));
			transData.setEaErrorOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
			transData.setLastNameOffset(ByteOrderConverter.swap(parameterBuffer.getShort()));
		}
		struct = new TransStruct[transData.getSearchCount()];
		for(int i =0 ; i< transData.getSearchCount();  i++){
			struct[i] = mapper.getStruct(FindInformationLevel.parse( ((FindNext2Request)((Transaction2Request)session.getUseSessionData()).getTransaction2Data()).getInformationLevel()));
			if(struct[i] == null){
	//			System.out.println("info Level = " +FindInformationLevel.parse( ((FindNext2Request)((Transaction2Request)session.getUseSessionData()).getTransaction2Data()).getInformationLevel()));
				break;
			}
			if(dataBuffer.readableBytes() == 0){
				break;
			}
			dataBuffer.discardReadBytes();
			struct[i].parse(dataBuffer , session);
		}
		transData.setInfoStruct(struct);
		// TODO : data parsing
		return transData;
	}

}
