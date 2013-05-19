package org.araqne.pcap.smb.transreq;

import org.araqne.pcap.smb.TransData;

public class RawReadNmpipeRequest implements TransData{
	short subCommand;
	short fid;
	public short getSubCommand() {
		return subCommand;
	}
	public void setSubCommand(short subCommand) {
		this.subCommand = subCommand;
	}
	public short getFid() {
		return fid;
	}
	public void setFid(short fid) {
		this.fid = fid;
	}
	@Override
	public String toString(){
		return String.format("");
	}
}