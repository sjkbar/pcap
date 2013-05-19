/*
 * Copyright 2011 Future Systems, Inc
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.araqne.pcap.netbios.rr;

import org.araqne.pcap.netbios.NetBiosSessionData;
import org.araqne.pcap.util.Buffer;

public class SessionMessage implements NetBiosSessionData {
	private Buffer buffer; // this use session message only

	private SessionMessage(Buffer buffer) {
		this.buffer = buffer;
	}

	public static NetBiosSessionData parse(Buffer b) {
		return new SessionMessage(b);
	}

	@Override
	public String toString() {
		return String.format("netbios session: message buffer length=%d", buffer.readableBytes());
	}

	@Override
	public Buffer getBuffer() {
		// TODO Auto-generated method stub
		return buffer;
	}
}
