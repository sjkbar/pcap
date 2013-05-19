package org.araqne.pcap.smb;

import java.util.HashMap;
import java.util.Map;

import org.araqne.pcap.smb.rr.SetInformationLevel;
import org.araqne.pcap.smb.trans2struct.setinfostruct.SmbInfoSeteas;
import org.araqne.pcap.smb.trans2struct.setinfostruct.SmbInfoStandard;
import org.araqne.pcap.smb.trans2struct.setinfostruct.SmbSetFileAllocationInfo;
import org.araqne.pcap.smb.trans2struct.setinfostruct.SmbSetFileBasicInfo;
import org.araqne.pcap.smb.trans2struct.setinfostruct.SmbSetFileDispositionInfo;
import org.araqne.pcap.smb.trans2struct.setinfostruct.SmbSetFileEndOfFileInfo;

public class SetInfoLevelMapper {

	private Map<SetInformationLevel, TransStruct> setInfoMap = new HashMap<SetInformationLevel, TransStruct>();
	public SetInfoLevelMapper() {
		setInfoMap.put(SetInformationLevel.SmbInfoStandard, new SmbInfoStandard());
		setInfoMap.put(SetInformationLevel.SmbInfoSetEas , new SmbInfoSeteas());
		setInfoMap.put(SetInformationLevel.SmbSetFileBasicInfo, new SmbSetFileBasicInfo());
		setInfoMap.put(SetInformationLevel.SmbSetFileDspositionInfo, new SmbSetFileDispositionInfo());
		setInfoMap.put(SetInformationLevel.SmbSetFileAllocationInfo , new SmbSetFileAllocationInfo());
		setInfoMap.put(SetInformationLevel.SmbSetFileEndOfFileInfo, new SmbSetFileEndOfFileInfo());
		
	}
}
