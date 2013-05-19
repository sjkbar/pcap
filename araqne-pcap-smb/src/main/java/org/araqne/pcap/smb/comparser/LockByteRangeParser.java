package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.LockByteRangeRequest;
import org.araqne.pcap.smb.response.LockByteRangeResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
// 0x0c
public class LockByteRangeParser implements SmbDataParser{
	@Override
	public SmbData parseRequest(SmbHeader h,Buffer b , SmbSession session) {
		LockByteRangeRequest data = new LockByteRangeRequest();
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setCountOfBytesToLock(ByteOrderConverter.swap(b.getInt()));
		data.setLockOffsetInBytes(ByteOrderConverter.swap(b.getInt()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		LockByteRangeResponse data = new LockByteRangeResponse();
		data.setWordCount(b.get());
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
