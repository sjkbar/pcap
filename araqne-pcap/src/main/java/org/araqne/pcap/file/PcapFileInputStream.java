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
package org.araqne.pcap.file;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import org.araqne.pcap.PcapInputStream;
import org.araqne.pcap.packet.PacketHeader;
import org.araqne.pcap.packet.PcapPacket;
import org.araqne.pcap.util.Buffer;
import org.araqne.pcap.util.ByteOrderConverter;
import org.araqne.pcap.util.ChainBuffer;

/**
 * PcapFileInputStream reads pcap packet stream from pcap dump file. At this
 * point of time, commonly used format is 2.4 version. It can read file
 * regardless of byte order because of the magic number of global header.
 * 
 * @author mindori
 * @see http://wiki.wireshark.org/Development/LibpcapFileFormat
 */
public class PcapFileInputStream implements PcapInputStream {
	private long position;
	private DataInputStream is;
	private GlobalHeader globalHeader;

	// for packet header i/o
	private byte[] headerBuffer = new byte[16];

	/**
	 * Opens pcap file input stream.
	 * 
	 * @param file
	 *            the file to be opened for reading
	 * @throws FileNotFoundException
	 *             if the file does not exist, is a directory rather than a
	 *             regular file, or for some other reason cannot be opened for
	 *             reading.
	 */
	public PcapFileInputStream(InputStream stream) throws IOException {
		is = new DataInputStream(stream);
		readGlobalHeader();
	}

	/**
	 * Opens pcap file input stream.
	 * 
	 * @param file
	 *            the file to be opened for reading
	 * @throws FileNotFoundException
	 *             if the file does not exist, is a directory rather than a
	 *             regular file, or for some other reason cannot be opened for
	 *             reading.
	 */
	public PcapFileInputStream(File file) throws IOException {
		is = new DataInputStream(new FileInputStream(file));
		readGlobalHeader();
	}

	/**
	 * Reads a packet from pcap file.
	 * 
	 * @exception EOFException
	 *                if this input stream reaches the end before reading four
	 *                bytes.
	 * @exception IOException
	 *                the stream has been closed and the contained input stream
	 *                does not support reading after close, or another I/O error
	 *                occurs.
	 */
	@Override
	public PcapPacket getPacket() throws IOException {
		return readPacket(globalHeader.getMagicNumber());
	}

	public GlobalHeader getGlobalHeader() {
		return globalHeader;
	}

	/**
	 * return next file read position
	 */
	public long getPosition() {
		return position;
	}

	public void skip(long offset) throws IOException {
		is.skipBytes((int) offset);
	}

	private void readGlobalHeader() throws IOException {
		int magic = is.readInt();
		short major = is.readShort();
		short minor = is.readShort();
		int tz = is.readInt();
		int sigfigs = is.readInt();
		int snaplen = is.readInt();
		int network = is.readInt();

		position += 24;
		globalHeader = new GlobalHeader(magic, major, minor, tz, sigfigs, snaplen, network);

		if (globalHeader.getMagicNumber() == 0xD4C3B2A1)
			globalHeader.swapByteOrder();
	}

	private PcapPacket readPacket(int magicNumber) throws IOException, EOFException {
		long lastPosition = position;
		try {
			PacketHeader packetHeader = readPacketHeader(magicNumber);
			Buffer packetData = readPacketData(packetHeader.getInclLen());
			return new PcapPacket(packetHeader, packetData);
		} catch (IOException e) {
			position = lastPosition;
			throw e;
		}
	}

	private PacketHeader readPacketHeader(int magicNumber) throws IOException, EOFException {
		is.readFully(headerBuffer);
		position += 16;

		ByteBuffer bb = ByteBuffer.wrap(headerBuffer);

		int tsSec = bb.getInt();
		int tsUsec = bb.getInt();
		int inclLen = bb.getInt();
		int origLen = bb.getInt();

		if (magicNumber == 0xD4C3B2A1) {
			tsSec = ByteOrderConverter.swap(tsSec);
			tsUsec = ByteOrderConverter.swap(tsUsec);
			inclLen = ByteOrderConverter.swap(inclLen);
			origLen = ByteOrderConverter.swap(origLen);
		}

		return new PacketHeader(tsSec, tsUsec, inclLen, origLen);
	}

	private Buffer readPacketData(int packetLength) throws IOException {
		byte[] packets = new byte[packetLength];
		int readBytes = is.read(packets);
		if (readBytes > 0)
			position += readBytes;

		Buffer payload = new ChainBuffer();
		payload.addLast(packets);
		return payload;
	}

	/**
	 * Closes pcap file handle.
	 */
	public void close() throws IOException {
		is.close();
	}
}
