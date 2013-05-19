package org.araqne.pcap.smb.trans2req;

import org.araqne.pcap.smb.TransData;

public class QueryFsInformationRequest implements TransData{
	short subcommand;
	short informationLevel;
	//Transaction2Command inforLevel;
	// there is no data
	
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
	@Override
	public String toString(){
		return String.format("Trans2 Second Level : Query Fs Information Request \n" +
				"subCommand = 0x%s\n" +
				"informationLevel = 0x%s\n",
				Integer.toHexString(this.subcommand),
				Integer.toHexString(this.informationLevel));
	}
}
