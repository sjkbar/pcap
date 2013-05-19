package org.araqne.pcap.smb.trans2struct.setinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.smb.structure.SmbFeaList;
import org.araqne.pcap.util.Buffer;

public class SmbInfoSeteas implements TransStruct {

	SmbFeaList extendedAttributeList;

	public SmbFeaList getExtendedAttributeList() {
		return extendedAttributeList;
	}

	public void setExtendedAttributeList(SmbFeaList extendedAttributeList) {
		this.extendedAttributeList = extendedAttributeList;
	}

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		extendedAttributeList = new SmbFeaList();
		extendedAttributeList.parse(b);
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
