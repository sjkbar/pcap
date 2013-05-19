package org.araqne.pcap.smb.comparser;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.request.WriteMPXRequest;
import org.araqne.pcap.smb.response.WriteMPXResponse;
import org.araqne.pcap.smb.structure.SmbData;
import org.araqne.pcap.smb.structure.SmbHeader;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class WriteMPXParser implements SmbDataParser{
	@Override
	public SmbData parseRequest(SmbHeader h , Buffer b , SmbSession session) {
		WriteMPXRequest data = new WriteMPXRequest();
		byte []pad;
		byte []buffer;
		data.setWordCount(b.get());
		data.setFid(ByteOrderConverter.swap(b.getShort()));
		data.setTotalByteCount(ByteOrderConverter.swap(b.getShort()));
		data.setReserved(ByteOrderConverter.swap(b.getShort()));
		data.setByteOffsetToBeginwrite(ByteOrderConverter.swap(b.getInt()));
		data.setTimeout(ByteOrderConverter.swap(b.getInt()));
		data.setWriteMode(ByteOrderConverter.swap(b.getShort()));
		data.setReqMask(ByteOrderConverter.swap(b.getInt()));
		data.setDataLength(ByteOrderConverter.swap(b.getShort()));
		data.setDataOffset(ByteOrderConverter.swap(b.getShort()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		if(b.readableBytes() != data.getByteCount()){
			data.setMalformed(true);
			return data;
		}
		pad = new byte[data.getDataOffset()-25-32];
		buffer = new byte[data.getDataLength()];
		if(pad.length !=0){
			b.gets(pad);
			data.setPad(pad);
		}
		b.gets(buffer);
		data.setBuffer(buffer);
		return data;
	}
	@Override
	public SmbData parseResponse(SmbHeader h , Buffer b ,SmbSession session) {
		WriteMPXResponse data = new WriteMPXResponse();
		data.setWordCount(b.get());
		data.setResMask(ByteOrderConverter.swap(b.getInt()));
		data.setByteCount(ByteOrderConverter.swap(b.getShort()));
		return data;
	}
}
