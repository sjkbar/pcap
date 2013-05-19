package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.UnlockByteRangeRequest;
import org.araqne.pcap.smb.response.UnlockByteRangeResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class UnlockByteRangeParser implements SmbDataParser{
	
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		UnlockByteRangeRequest data = new UnlockByteRangeRequest();
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x05){
			data.setFid(ByteOrderConverter.swap(b.getShort()));
			data.setCountOfBytesToLock(ByteOrderConverter.swap(b.getInt()));
			data.setUnLockOffsetInBytes(ByteOrderConverter.swap(b.getInt()));
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		UnlockByteRangeResponse data = new UnlockByteRangeResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
