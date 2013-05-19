package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.LockAndReadRequest;
import org.araqne.pcap.smb.response.LockAndReadResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class LockAndReadParser implements SmbDataParser{

	@Override
	public SmbData parseRequest(SmbHeader h ,Buffer b , SmbSession session) {
		LockAndReadRequest data = new LockAndReadRequest();
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x05){
			data.setFid(ByteOrderConverter.swap(b.getShort()));
			data.setCountOfBytesToRead(ByteOrderConverter.swap(b.getShort()));
			data.setReadOffsetInBytes(ByteOrderConverter.swap(b.getInt()));
			data.setEstimateOfRemainingBytesToBeRead(ByteOrderConverter.swap(b.getShort()));
		}
		else{
			data.setMalformed(true);
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h,Buffer b ,SmbSession session) {
		LockAndReadResponse data = new LockAndReadResponse();
		byte []reserved = new byte[8];
		byte []bytes;
		data.setWordCount(b.get());
		if(data.getWordCount() == 0x05){
			data.setCountofBytesReturned(ByteOrderConverter.swap(b.getShort()));
			b.gets(reserved);
			data.setReserved(reserved);
		}
		else{
			data.setMalformed(true);
		}
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		else if(b.readableBytes() == 0){
			data.setMalformed(true);
			return data;
		}
		data.setBufferType(b.get());
		data.setCountOfBytesRead(ByteOrderConverter.swap(b.getShort()));
		bytes = new byte[data.getCountOfBytesRead()];
		b.gets(bytes);
		data.setBytes(bytes);
		return data;
	}
}
