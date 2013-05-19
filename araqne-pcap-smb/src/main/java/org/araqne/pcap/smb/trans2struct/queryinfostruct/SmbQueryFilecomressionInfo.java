package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFilecomressionInfo implements TransStruct{

	long compressedFileSize;
	short compressionFormat;
	byte compressionUnitShft;
	byte chunkShift;
	byte clusterShift;
	byte []reserved;// = new byte[3]; 
	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		compressedFileSize = ByteOrderConverter.swap(b.getLong());
		compressionFormat = ByteOrderConverter.swap(b.getShort());
		compressionUnitShft = b.get();
		chunkShift = b.get();
		clusterShift = b.get();
		reserved = new byte[3];
		b.gets(reserved);
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
