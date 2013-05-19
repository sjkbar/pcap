package org.araqne.pcap.smb.response;
import org.araqne.pcap.smb.structure.SmbData;
//0x2A
public class MoveResponse implements SmbData{
	boolean malformed = false;
	// no longer used
	// return status not implemented
	@Override
	public boolean isMalformed() {
		// TODO Auto-generated method stub
		return malformed;
	}
	@Override
	public void setMalformed(boolean malformed) {
		this.malformed = malformed;
	}
	@Override
	public String toString(){
		return String.format("First Level : Move Response\n" +
				"isMalformed = %s\n",
				this.malformed);
	}
}
