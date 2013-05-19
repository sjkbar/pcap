package org.araqne.pcap.smb.transresp;

import org.araqne.pcap.smb.TransData;

public class WaitNmpipeResponse implements TransData{
	/// there is no response
	@Override
	public String toString(){
		return String.format("");
	}
}
