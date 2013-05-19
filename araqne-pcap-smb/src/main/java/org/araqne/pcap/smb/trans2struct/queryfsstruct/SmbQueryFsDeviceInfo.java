package org.araqne.pcap.smb.trans2struct.queryfsstruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFsDeviceInfo implements TransStruct{

	int deviceType;
	int deviceCharacteristcis;
	public int getDeviceType() {
		return deviceType;
	}
	public void setDeviceType(int deviceType) {
		this.deviceType = deviceType;
	}
	public int getDeviceCharacteristcis() {
		return deviceCharacteristcis;
	}
	public void setDeviceCharacteristcis(int deviceCharacteristcis) {
		this.deviceCharacteristcis = deviceCharacteristcis;
	}
	public TransStruct parse(Buffer b , SmbSession session){
		deviceType = ByteOrderConverter.swap(b.getInt());
		deviceCharacteristcis = ByteOrderConverter.swap(b.getInt());
		return this;
	}
	@Override
	public String toString(){
		return String.format("Third Level Structure : Smb Info Fs Device Info\n" +
				"deviceTupe = 0x%s , deviceCharacteristics = 0x%s",
				Integer.toHexString(this.deviceType),  Integer.toHexString(this.deviceCharacteristcis));
	}
}
