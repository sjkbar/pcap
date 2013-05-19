package org.araqne.pcap.smb.trans2resp;

import org.araqne.pcap.smb.TransData;

public class SessionSetupResponse implements TransData{
	@Override
	public String toString(){
		return String.format("Trans2 Seconde Level : Session Setup Response\n");
	}
}
