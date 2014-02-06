/*
 * Copyright 2010 NCHOVY
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
package org.araqne.pcap.live;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

import org.araqne.pcap.PcapInputStream;
import org.araqne.pcap.PcapOutputStream;
import org.araqne.pcap.packet.PacketHeader;
import org.araqne.pcap.packet.PacketPayload;
import org.araqne.pcap.packet.PcapPacket;
import org.araqne.pcap.util.Buffer;

/**
 * PcapDevice is a JNI wrapper for libpcap. It can capture live traffic from
 * network interface, and inject arbitrary packets to network interface.
 * 
 * @author delmitz
 * @since 1.1
 */
public class PcapDevice implements PcapInputStream, PcapOutputStream {
	static {
		// araqne_pcap.dll or libaraqne_pcap.so
		System.loadLibrary("araqne_pcap");
	}

	private boolean isOpen = true;
	private int handle;
	private PcapDeviceMetadata metadata;
	private Set<PcapDeviceEventListener> callbacks;
	private ByteBuffer buffer;
	private ByteBuffer txbuffer;
	private int milliseconds;
	private int offset, txoffset;

	PcapDevice(PcapDeviceMetadata metadata, int handle, String name, int snaplen, boolean promisc, int milliseconds)
			throws IOException {
		this.metadata = metadata;
		this.handle = handle;
		this.callbacks = Collections.synchronizedSet(new HashSet<PcapDeviceEventListener>());
		this.milliseconds = milliseconds;
		buffer = openBuffer(handle, name, snaplen, promisc, milliseconds);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		txbuffer = getTxBuffer(buffer);
		txbuffer.order(ByteOrder.LITTLE_ENDIAN);
		txoffset = writeBuffer(txbuffer, -1);
		// openBuffer(handle, name, snaplen, promisc, milliseconds);
	}

	public int getHandle() {
		return handle;
	}

	public PcapDeviceMetadata getMetadata() {
		return metadata;
	}

	public void addListener(PcapDeviceEventListener callback) {
		callbacks.add(callback);
	}

	public void removeListener(PcapDeviceEventListener callback) {
		callbacks.remove(callback);
	}

	private native void open(int handle, String name, int snaplen, boolean promisc, int milliseconds) throws IOException;

	private native ByteBuffer openBuffer(int handle, String name, int snaplen, boolean promisc, int milliseconds)
			throws IOException;

	/**
	 * Receives a packet from the device.
	 * 
	 * @throws IOException
	 *             if the device is not opened, or timeout occurred in blocking
	 *             mode.
	 */
	@Deprecated
	@Override
	public PcapPacket getPacket() throws IOException {
		verify();
		return getPacket(handle);
	}

	public List<PcapPacket> getPackets() {
		int len, pkt = 0, timeout = milliseconds;
		int tsSec, tsUsec, inclLen, origLen;
		ArrayList<PcapPacket> packetList = new ArrayList<PcapPacket>();

		while (true) {
			int ret = getPacketBuffered(buffer, offset, timeout);
			if (ret >= 0) {
				offset = ret;
				buffer.position(offset);
				len = buffer.getInt();
				tsSec = buffer.getInt();
				tsUsec = buffer.getInt();
				inclLen = buffer.getInt();
				origLen = buffer.getInt();
				len -= 16;
				byte data[] = new byte[len];
				buffer.get(data, 0, len);

				PacketHeader ph = new PacketHeader(tsSec, tsUsec, inclLen, origLen);
				PacketPayload pl = new PacketPayload(data);
				PcapPacket pp = new PcapPacket(ph, pl);
				packetList.add(pp);
				pkt++;
				if (pkt >= 128)
					return packetList;
				timeout = 0;
			} else {
				return packetList;
			}
		}
	}

	private native PcapPacket getPacket(int id) throws IOException;

	private native int getPacketBuffered(ByteBuffer buf, int freepos, int timeout);

	private native ByteBuffer getTxBuffer(ByteBuffer buf);

	private native int writeBuffer(ByteBuffer buf, int len);

	/**
	 * Injects a packet to the device. You can even send malformed packet.
	 * 
	 * @throws IOException
	 *             if the device is not opened.
	 */
	@Override
	public void write(PcapPacket packet) throws IOException {
		verify();

		Buffer buffer = packet.getPacketData();
		byte[] b = new byte[buffer.readableBytes()];
		buffer.gets(b);

		write(handle, b, 0, b.length);
	}

	public void write(Buffer buffer) throws IOException {
		verify();

		byte[] b = new byte[buffer.readableBytes()];
		buffer.gets(b);
		write(handle, b, 0, b.length);
	}

	/**
	 * Injects a raw packet
	 * 
	 * @param b
	 *            the raw data
	 * @throws IOException
	 *             if the device is not opened.
	 */
	public void write(byte[] b) throws IOException {
		verify();
		write(handle, b, 0, b.length);
	}

	// private native void write(int id, byte[] packet, int offset, int limit)
	// throws IOException;
	private void write(int id, byte[] packet, int offset, int limit) {
		txbuffer.position(txoffset + 12);
		txbuffer.put(packet, offset, limit);
		txoffset = writeBuffer(txbuffer, limit);
	}

	/**
	 * Changes blocking mode of the device.
	 * 
	 * @param nonblock
	 *            true for non-blocking mode.
	 * @throws IOException
	 *             if the device is not opened.
	 */
	public void setNonblock(boolean nonblock) throws IOException {
		verify();
		setNonblock(handle, nonblock ? 1 : 0);
	}

	private native void setNonblock(int id, int nonblock) throws IOException;

	/**
	 * Gets blocking mode of the device.
	 * 
	 * @return true if the devices is in non-blocking mode.
	 * @throws IOException
	 *             if the device is not opened.
	 */
	public boolean isNonblock() throws IOException {
		verify();
		return isNonblock(handle);
	}

	private native boolean isNonblock(int id) throws IOException;

	public void setFilter(String filter) throws IOException {
		setFilter(filter, false);
	}

	/**
	 * Sets berkeley packet filter or BPF.
	 * 
	 * @see http://biot.com/capstats/bpf.html
	 * @param filter
	 *            the bpf expression
	 * @param optimize
	 *            true for optimization
	 * @throws IOException
	 *             if the device is not opened.
	 * @throws IllegalArgumentException
	 *             if error occurred in pcap_compile.
	 */
	public void setFilter(String filter, boolean optimize) throws IOException, IllegalArgumentException {
		verify();
		setFilter(handle, (filter != null ? filter : ""), optimize ? 1 : 0, metadata.getNetworkPrefixLength());
	}

	private native void setFilter(int id, String filter, int optimize, int netmask) throws IOException, IllegalArgumentException;

	/**
	 * Gets pcap packet capture statistics from libpcap.
	 * 
	 * @return the packet capture statistics
	 * @throws IOException
	 *             if the device is not opened.
	 */
	public PcapStat getStat() throws IOException {
		verify();
		return getStat(handle);
	}

	private native PcapStat getStat(int id) throws IOException;

	/**
	 * s the packet capture device.
	 */
	@Override
	public void close() throws IOException {
		verify();
		closeBuffer(buffer);// handle);
		isOpen = false;

		for (PcapDeviceEventListener callback : callbacks) {
			callback.onClosed(this);
		}
	}

	private native void close(int id) throws IOException;

	private native void closeBuffer(ByteBuffer buf);

	public static native String getPcapLibVersion();

	@Override
	public void flush() throws IOException {
		// nothing, live injection does not buffering.
	}

	@Override
	public String toString() {
		return String.format("NetworkInterface [name=%s, description=%s, macAddress=%s]", metadata.getName(),
				metadata.getDescription(), metadata.getMacAddress());
	}

	public boolean isOpen() {
		return isOpen;
	}

	private void verify() throws IOException {
		if (!isOpen)
			throw new IOException("Device is not opened");
	}
}
