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
package org.apache.haox.asn1;

import org.apache.haox.asn1.type.Asn1Collection;
import org.apache.haox.asn1.type.Asn1Simple;
import org.apache.haox.asn1.type.Asn1Type;

public class Asn1Factory {

    public static Asn1Type create(int tagNo) {
        UniversalTag tagNoEnum = UniversalTag.fromValue(tagNo);
        if (tagNoEnum != UniversalTag.UNKNOWN) {
            return create(tagNoEnum);
        }
        throw new IllegalArgumentException("Unexpected tag " + tagNo);
    }

    public static Asn1Type create(UniversalTag tagNo) {
        if (Asn1Simple.isSimple(tagNo)) {
            return Asn1Simple.createSimple(tagNo);
        } else if (Asn1Collection.isCollection(tagNo)) {
            return Asn1Collection.createCollection(tagNo);
        }
        throw new IllegalArgumentException("Unexpected tag " + tagNo);
    }
}
