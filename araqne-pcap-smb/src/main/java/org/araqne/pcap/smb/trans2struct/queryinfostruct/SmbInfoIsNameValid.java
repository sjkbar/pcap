package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;

public class SmbInfoIsNameValid implements TransStruct{

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		return null;
	}
	@Override
	public String toString(){
		return String.format("");
	}
	// no parameter return
}
