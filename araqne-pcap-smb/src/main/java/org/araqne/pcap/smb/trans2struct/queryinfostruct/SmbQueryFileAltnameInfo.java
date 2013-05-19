package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFileAltnameInfo implements TransStruct{

	int fileNameLength;
	String fileName;
	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		fileNameLength = ByteOrderConverter.swap(b.getInt());
		fileName = NetBiosNameCodec.readSmbUnicodeName(b, fileNameLength);
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
