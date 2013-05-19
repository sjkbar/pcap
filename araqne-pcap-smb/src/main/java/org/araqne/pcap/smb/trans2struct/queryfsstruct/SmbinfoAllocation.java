package org.araqne.pcap.smb.trans2struct.queryfsstruct;

import org.araqne.pcap.smb.SmbSession;
import org.araqne.pcap.smb.TransStruct;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;

public class SmbinfoAllocation implements TransStruct{

	int idFileSystem;
	int cSectorUnit;
	int cUnit;
	int cUnitAvailable;
	short cbSector;
	public int getIdFileSystem() {
		return idFileSystem;
	}
	public void setIdFileSystem(int idFileSystem) {
		this.idFileSystem = idFileSystem;
	}
	public int getcSectorUnit() {
		return cSectorUnit;
	}
	public void setcSectorUnit(int cSectorUnit) {
		this.cSectorUnit = cSectorUnit;
	}
	public int getcUnit() {
		return cUnit;
	}
	public void setcUnit(int cUnit) {
		this.cUnit = cUnit;
	}
	public int getcUnitAvailable() {
		return cUnitAvailable;
	}
	public void setcUnitAvailable(int cUnitAvailable) {
		this.cUnitAvailable = cUnitAvailable;
	}
	public short getCbSector() {
		return cbSector;
	}
	public void setCbSector(short cbSector) {
		this.cbSector = cbSector;
	}
	public TransStruct parse(Buffer b , SmbSession session){
		idFileSystem = ByteOrderConverter.swap(b.getInt());
		cSectorUnit = ByteOrderConverter.swap(b.getInt());
		cUnit = ByteOrderConverter.swap(b.getInt());
		cUnitAvailable = ByteOrderConverter.swap(b.getInt());
		cbSector = ByteOrderConverter.swap(b.getShort());
		return this;
	}
	@Override
	public String toString(){
		return String.format("Third Level Structure : Smb Info Allocation" +
				"idFileSystem = 0x%s , cSectorUnit = 0x%s, cUnit = 0x%s" +
				"cbSector = 0x%s\n",
				Integer.toHexString(this.idFileSystem) , Integer.toHexString(this.cSectorUnit) , Integer.toHexString(this.cUnit),
				Integer.toHexString(this.cbSector));
	}
}
