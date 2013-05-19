package org.araqne.pcap.smb.trans2struct.queryinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.smb.structure.SmbFeaList;
import org.araqne.pcap.util.Buffer;

public class SmbInfoQueryAllEas implements TransStruct{

	SmbFeaList extendedAttributesList;

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		extendedAttributesList = new SmbFeaList();
		extendedAttributesList.parse(b);
		return this;
	}
	@Override
	public String toString(){
		return String.format("Third Level Structure : Smb Info Query All Eas\n" +
				"extendedAttributesList = %s\n",
				this.extendedAttributesList);
	}
}
