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
package org.apache.kerberos.kerb.codec.kerberos;


import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.codec.KrbCodec;
import org.apache.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;

import java.io.IOException;

public class KerberosApRequest {
    private ApReq apReq;
    private KerberosTicket ticket;

    public KerberosApRequest(byte[] token, EncryptionKey key) throws Exception {
        if(token.length <= 0) {
            throw new IOException("kerberos request empty");
        }

        apReq = KrbCodec.decode(token, ApReq.class);
        ticket = new KerberosTicket(apReq.getTicket(), apReq.getApOptions(), key);
    }

    public ApOptions getApOptions() throws KrbException {
        return apReq.getApOptions();
    }

    public KerberosTicket getTicket() {
        return ticket;
    }
}
