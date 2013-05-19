package org.araqne.pcap.smb.request;
import org.araqne.pcap.smb.structure.SmbData;
//0x2A
public class MoveRequest implements SmbData{

	boolean malformed = false;
	@Override
	public boolean isMalformed() {
		// TODO Auto-generated method stub
		return malformed;
	}
	@Override
	public void setMalformed(boolean malformed) {
		this.malformed = malformed;
	}
	// no longer used
	// return status not implemented
	@Override
	public String toString(){
		return String.format("First Level : Move Request\n"+
				"isMalformed = %s\n",
				this.malformed);
	}
}
