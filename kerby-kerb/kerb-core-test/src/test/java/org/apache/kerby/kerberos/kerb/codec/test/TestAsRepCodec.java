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
package org.apache.kerby.kerberos.kerb.codec.test;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.spec.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test AsRep message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestAsRepCodec {

    @Test
    public void test() throws IOException, KrbException, ParseException {
        byte[] bytes = CodecTestUtil.readBinaryFile("/asrep.token");
        ByteBuffer asRepToken = ByteBuffer.wrap(bytes);

        AsRep asRep = new AsRep();
        asRep.decode(asRepToken);

        assertThat(asRep.getPvno()).isEqualTo(5);
        assertThat(asRep.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
        assertThat(asRep.getCrealm()).isEqualTo("DENYDC.COM");

        PrincipalName cName = asRep.getCname();
        assertThat(cName.getNameType()).isEqualTo(NameType.NT_PRINCIPAL);
        assertThat(cName.getNameStrings()).hasSize(1).contains("u5");

        Ticket ticket = asRep.getTicket();
        assertThat(ticket.getTktvno()).isEqualTo(5);
        assertThat(ticket.getRealm()).isEqualTo("DENYDC.COM");
        PrincipalName sName = ticket.getSname();
        assertThat(sName.getNameType()).isEqualTo(NameType.NT_SRV_INST);
        assertThat(sName.getNameStrings()).hasSize(2)
                .contains("krbtgt", "DENYDC.COM");

        //test for encrypted data
        EncryptionKey key = CodecTestUtil.getKeyFromDefaultKeytab(EncryptionType.ARCFOUR_HMAC);
        byte[] decryptedData = EncryptionHandler.decrypt(asRep.getEncryptedEncPart(), key, KeyUsage.AS_REP_ENCPART);
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        encKdcRepPart.decode(decryptedData);

        List<LastReqEntry> lastReqEntries = encKdcRepPart.getLastReq().getElements();
        assertThat(lastReqEntries).hasSize(1);
        LastReqEntry entry = lastReqEntries.get(0);
        assertThat(entry.getLrType()).isEqualTo(LastReqType.NONE);
        assertThat(entry.getLrValue().getTime())
                .isEqualTo(CodecTestUtil.parseDateByDefaultFormat("20050816094134"));

        assertThat(encKdcRepPart.getNonce()).isEqualTo(854491315);
        assertThat(encKdcRepPart.getKeyExpiration().getTime())
                .isEqualTo(CodecTestUtil.parseDateByDefaultFormat("20370914024805"));
        byte[] ticketFlags = new byte[]{0,1,0,0,0,0,0,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        assertThat(encKdcRepPart.getFlags().getValue()).isEqualTo(ticketFlags);
        assertThat(encKdcRepPart.getAuthTime().getTime())
                .isEqualTo(CodecTestUtil.parseDateByDefaultFormat("20050816094134"));
        assertThat(encKdcRepPart.getStartTime().getTime())
                .isEqualTo(CodecTestUtil.parseDateByDefaultFormat("20050816094134"));
        assertThat(encKdcRepPart.getEndTime().getTime())
                .isEqualTo(CodecTestUtil.parseDateByDefaultFormat("20050817050000"));
        assertThat(encKdcRepPart.getSrealm()).isEqualTo("DENYDC.COM");

        PrincipalName encSName = encKdcRepPart.getSname();
        assertThat(encSName.getName()).isEqualTo("krbtgt/DENYDC.COM");
        assertThat(encSName.getNameType()).isEqualTo(NameType.NT_SRV_INST);
        assertThat(encSName.getNameStrings()).hasSize(2).contains("krbtgt").contains("DENYDC.COM");
    }
}
