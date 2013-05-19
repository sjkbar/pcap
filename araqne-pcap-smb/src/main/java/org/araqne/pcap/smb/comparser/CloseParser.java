package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.CloseRequest;
import org.araqne.pcap.smb.response.CloseResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class CloseParser implements SmbDataParser{

	//param
	byte resWordCount; 
	//data
	short resByteCount;
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		CloseRequest data = new CloseRequest();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setLastTimeModified(ByteOrderConverter.swap(b.getInt()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b,SmbSession session) {
		CloseResponse data = new CloseResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	} 
}
