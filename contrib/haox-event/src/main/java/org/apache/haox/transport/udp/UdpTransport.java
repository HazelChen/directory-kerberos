/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.haox.transport.udp;

import org.apache.haox.transport.Transport;
import org.apache.haox.transport.buffer.TransBuffer;
import org.apache.haox.transport.event.MessageEvent;
import org.apache.haox.transport.event.TransportEvent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

public class UdpTransport extends Transport {
    private DatagramChannel channel;

    protected TransBuffer recvBuffer;

    public UdpTransport(DatagramChannel channel,
                        InetSocketAddress remoteAddress) {
        super(remoteAddress);
        this.channel = channel;
        this.recvBuffer = new TransBuffer();
    }

    protected void onRecvData(ByteBuffer data) {
        if (data != null) {
            recvBuffer.write(data);
            dispatcher.dispatch(TransportEvent.createReadableTransportEvent(this));
        }
    }

    @Override
    public void onReadable() throws IOException {
        super.onReadable();

        if (! recvBuffer.isEmpty()) {
            ByteBuffer message = recvBuffer.read();
            dispatcher.dispatch(MessageEvent.createInboundMessageEvent(this, message));
        }
    }

    @Override
    protected void sendOutMessage(ByteBuffer message) throws IOException {
        channel.send(message, getRemoteAddress());
    }
}
