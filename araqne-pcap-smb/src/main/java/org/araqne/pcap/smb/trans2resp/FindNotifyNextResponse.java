package org.araqne.pcap.smb.trans2resp;

import org.araqne.pcap.smb.TransData;

public class FindNotifyNextResponse implements TransData{
	@Override
	public String toString(){
		return String.format("Trans2 Seconde Level : Find Notify Next Response\n");
	}
}
