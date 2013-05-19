package org.araqne.pcap.smb.transresp;

import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.rr.NamedPipeStatus;

public class QueryNmpipeStateResponse implements TransData{
	
	NamedPipeStatus status;

	public NamedPipeStatus getStatus() {
		return status;
	}

	public void setStatus(NamedPipeStatus status) {
		this.status = status;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}
