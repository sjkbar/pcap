package org.araqne.pcap.smb.trans2struct.findinfolevelstruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;

public class SmbFindFileIDFullDirectoryInfo implements TransStruct{

	@Override
	public TransStruct parse(Buffer b, SmbSession session) {
		return null;
	}
	@Override
	public String toString(){
		return String.format("Third Level Structure : Smb Find File Id Full Directory Info\n" +
				"this structure not implement");
	}
}
