package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFileStreamInfo implements TransStruct{

	int nextEnntryOffset;
	int streamNameLength;
	long streamSize;
	long streamAllocationSize;
	String streamName; // streamNameLength *2 bytes;
	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		nextEnntryOffset = ByteOrderConverter.swap(b.getInt());
		streamNameLength = ByteOrderConverter.swap(b.getInt());
		streamSize = ByteOrderConverter.swap(b.getLong());
		streamAllocationSize = ByteOrderConverter.swap(b.getLong());
		streamName = NetBiosNameCodec.readSmbUnicodeName(b, streamNameLength);
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
