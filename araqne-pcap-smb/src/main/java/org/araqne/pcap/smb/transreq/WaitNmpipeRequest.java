package org.araqne.pcap.smb.transreq;

import org.araqne.pcap.smb.TransData;

public class WaitNmpipeRequest implements TransData{
	short subcommand;
	short priority;
	public short getSubcommand() {
		return subcommand;
	}
	public void setSubcommand(short subcommand) {
		this.subcommand = subcommand;
	}
	public short getPriority() {
		return priority;
	}
	public void setPriority(short priority) {
		this.priority = priority;
	}
	@Override
	public String toString(){
		return String.format("");
	}
	
}
