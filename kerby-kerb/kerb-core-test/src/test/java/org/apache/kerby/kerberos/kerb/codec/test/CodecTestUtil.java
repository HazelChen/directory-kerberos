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

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.NameType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

public class CodecTestUtil {
    private static Keytab defaultKeytab;
    private static PrincipalName defaultPrincipalName;

    /**
     * The method is used by
     * TestAsReqCodec, TestAsRepCodec, TestTgsReqCodec, TestTgsRepCodec.
     * They all have a same keytab which is read from file "/server.keytab".
     */
    /*package*/ static EncryptionKey getKeyFromDefaultKeytab(EncryptionType encryptionType) throws IOException {
        if (defaultKeytab == null) {
            defaultKeytab = new Keytab();
            InputStream inputStream = CodecTestUtil.class.getResourceAsStream("/server.keytab");
            defaultKeytab.load(inputStream);
            inputStream.close();
        }

        if (defaultPrincipalName == null) {
            defaultPrincipalName = new PrincipalName();
            defaultPrincipalName.setNameStrings(Arrays.asList("HTTP/server.test.domain.com@DOMAIN.COM"));
            defaultPrincipalName.setNameType(NameType.NT_PRINCIPAL);
        }

        return defaultKeytab.getKey(defaultPrincipalName, encryptionType);
    }

    /*package*/ static byte[] readBinaryFile(String path) throws IOException {
        InputStream is = CodecTestUtil.class.getResourceAsStream(path);
        byte[] bytes = new byte[is.available()];
        is.read(bytes);
        is.close();
        return bytes;
    }

}
