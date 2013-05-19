package org.araqne.pcap.smb.trans2struct.queryfsstruct;

import org.araqne.pcap.netbios.NetBiosNameCodec;
import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbQueryFsVolumeInfo implements TransStruct{

	long volumeCreationTime;
	int serialNumber;
	int volumeLabelSize;// volumeLabelSize *2 -> unicode
	String volumeLabel;
	public long getVolumeCreationTime() {
		return volumeCreationTime;
	}
	public void setVolumeCreationTime(long volumeCreationTime) {
		this.volumeCreationTime = volumeCreationTime;
	}
	public int getSerialNumber() {
		return serialNumber;
	}
	public void setSerialNumber(int serialNumber) {
		this.serialNumber = serialNumber;
	}
	public int getVolumeLabelSize() {
		return volumeLabelSize;
	}
	public void setVolumeLabelSize(int volumeLabelSize) {
		this.volumeLabelSize = volumeLabelSize;
	}
	public String getVolumeLabel() {
		return volumeLabel;
	}
	public void setVolumeLabel(String volumeLabel) {
		this.volumeLabel = volumeLabel;
	}
	public TransStruct parse(Buffer b , SmbSession session){
		volumeCreationTime = ByteOrderConverter.swap(b.getLong());
		serialNumber = ByteOrderConverter.swap(b.getInt());
		volumeLabelSize = ByteOrderConverter.swap(b.getInt());
		volumeLabel = NetBiosNameCodec.readOemName(b, volumeLabelSize);
		return this;
	}
	@Override
	public String toString(){
		return String.format("Third Level Structure : Smb Info Fs Volume Info\n" +
				"volumeCreationTime = 0x%s , seialNumber = 0x%s , volumeLabelSize = 0x%s\n" +
				"volumeLabel = %s\n",
				Long.toHexString(this.volumeCreationTime) , Integer.toHexString(this.serialNumber) , Integer.toHexString(this.volumeLabelSize),
				this.volumeLabel);
	}
}
