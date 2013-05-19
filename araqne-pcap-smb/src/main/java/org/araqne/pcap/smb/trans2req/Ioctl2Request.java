package org.araqne.pcap.smb.trans2req;

import org.araqne.pcap.smb.TransData;

public class Ioctl2Request implements TransData{

	@Override
	public String toString(){
		return String.format("Trans2 Second Level : Ioctl2 Request\n" +
				"there is no implementation\n");
	}
}
