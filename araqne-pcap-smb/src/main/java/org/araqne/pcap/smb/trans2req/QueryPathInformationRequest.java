package org.araqne.pcap.smb.trans2req;

import org.araqne.pcap.smb.TransData;
import org.araqne.pcap.smb.structure.SmbGeaList;

public class QueryPathInformationRequest implements TransData{
	short subcommand;
	
	short informationLevel;
	int reserved;
	String fileName;
	SmbGeaList getExtendedAttrbitueList;
	public short getSubcommand() {
		return subcommand;
	}
	public void setSubcommand(short subcommand) {
		this.subcommand = subcommand;
	}
	public short getInformationLevel() {
		return informationLevel;
	}
	public void setInformationLevel(short informationLevel) {
		this.informationLevel = informationLevel;
	}
	public int getReserved() {
		return reserved;
	}
	public void setReserved(int reserved) {
		this.reserved = reserved;
	}
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	public SmbGeaList getGetExtendedAttrbitueList() {
		return getExtendedAttrbitueList;
	}
	public void setGetExtendedAttrbitueList(SmbGeaList getExtendedAttrbitueList) {
		this.getExtendedAttrbitueList = getExtendedAttrbitueList;
	}
	@Override
	public String toString(){
		return String.format("Trans2 Second Level : Qeury Path Information Request\n" +
				"subCommand = 0x%s\n" +
				"informationLevel = 0x%s , reserved = 0x%s\n" +
				"fileName = %s\n" +
				"extendedAttributesList = %s\n",
				Integer.toHexString(this.subcommand),
				Integer.toHexString(this.informationLevel), Integer.toHexString(this.reserved),
				this.fileName,
				this.getExtendedAttrbitueList);
	}
}
