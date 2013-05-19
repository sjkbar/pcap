package org.araqne.pcap.smb.trans2struct.setinfostruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;

public class SmbSetFileDispositionInfo implements TransStruct {

	byte deletePending;

	public byte getDeletePending() {
		return deletePending;
	}

	public void setDeletePending(byte deletePending) {
		this.deletePending = deletePending;
	}

	@Override
	public TransStruct parse(Buffer b , SmbSession session) {
		deletePending = b.get();
		return this;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
