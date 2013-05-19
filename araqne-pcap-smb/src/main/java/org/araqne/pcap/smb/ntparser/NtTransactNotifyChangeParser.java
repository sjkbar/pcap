package org.araqne.pcap.smb.ntparser;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.ntreq.NtTransactNotifyChangeRequest;
import org.araqne.pcap.smb.ntresp.NtTransactNotifyChangeResponse;
import org.araqne.pcap.smb.structure.FileNotifyInformation;
import org.araqne.pcap.smb.transparser.TransParser;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class NtTransactNotifyChangeParser implements TransParser{

	@Override
	public TransData parseRequest(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer) {
		NtTransactNotifyChangeRequest transData = new NtTransactNotifyChangeRequest();
		//start setupBuffer parse
		transData.setCompletionFiler(ByteOrderConverter.swap(setupBuffer.getInt()));
		transData.setFid(ByteOrderConverter.swap(setupBuffer.getShort()));
		transData.setWatchTree(setupBuffer.get());
		transData.setReserved(setupBuffer.get());
		// end of setupBuffer
		//there is no use of parameter and data Buffer
		return transData;
	}

	@Override
	public TransData parseResponse(Buffer setupBuffer , Buffer parameterBuffer,  Buffer dataBuffer , SmbSession session) {
		NtTransactNotifyChangeResponse transData = new NtTransactNotifyChangeResponse();
		FileNotifyInformation []fileNotifyInformation;
		byte []buff;
		byte []pad;
		int length =0;
		int i=0;
		// thereis no use of setup and data Buffers
		parameterBuffer.mark();
		while(true){ // count fileNotifyInformation structure
			i++;
			if(ByteOrderConverter.swap(parameterBuffer.getInt()) == 0x00000000){
				break;
			}
			parameterBuffer.skip(4);
			parameterBuffer.skip(ByteOrderConverter.swap(parameterBuffer.getInt()));
		}
		parameterBuffer.reset();
		fileNotifyInformation = new FileNotifyInformation[i]; 
		for(int j=0;j<i ;j++){
			fileNotifyInformation[j] = new FileNotifyInformation();
			fileNotifyInformation[j].setNextEntryoffset(ByteOrderConverter.swap(parameterBuffer.getInt()));
			fileNotifyInformation[j].setAction(ByteOrderConverter.swap(parameterBuffer.getInt()));
			fileNotifyInformation[j].setFileNameLength(ByteOrderConverter.swap(parameterBuffer.getInt()));
			buff = new byte[fileNotifyInformation[j].getFileNameLength()];
			parameterBuffer.gets(buff);
			fileNotifyInformation[j].setFileName(NetBiosNameCodec.SmbNameConvertToString(buff));
			length =  length+(fileNotifyInformation[j].getFileNameLength()) + 4+4+4;
			pad = new byte[fileNotifyInformation[j].getNextEntryoffset()-length];
			parameterBuffer.gets(pad);
		}
		transData.setFileNotifyInformation(fileNotifyInformation);
		return transData;
	}
}
