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

import org.apache.haox.asn1.EncodingOption;
import org.apache.haox.asn1.type.*;

/**
 * Ref. X.690-0207(http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf),
 * Annex A, A.1 ASN.1 description of the record structure
 */
public class PersonnelRecord extends TaggingSet {
    private static int NAME = 0;
    private static int TITLE = 1;
    private static int NUMBER = 2;
    private static int DATEOFHIRE= 3;
    private static int NAMEOFSPOUSE = 4;
    private static int CHILDREN = 5;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(NAME, -1, Name.class),
            new Asn1FieldInfo(TITLE, 0, Asn1VisibleString.class),
            new Asn1FieldInfo(NUMBER, -1, EmployeeNumber.class),
            new Asn1FieldInfo(DATEOFHIRE, 1, Date.class),
            new Asn1FieldInfo(NAMEOFSPOUSE, 2, Name.class),
            new Asn1FieldInfo(CHILDREN, 3, Children.class, true)
    };

    public PersonnelRecord() {
        super(0, fieldInfos, true);
        setEncodingOption(EncodingOption.IMPLICIT);
    }

    public void setName(Name name) {
        setFieldAs(NAME, name);
    }

    public Name getName() {
        return getFieldAs(NAME, Name.class);
    }

    public void setTitle(String title) {
        setFieldAs(TITLE, new Asn1VisibleString(title));
    }

    public String getTitle() {
        return getFieldAsString(TITLE);
    }

    public void setEmployeeNumber(EmployeeNumber employeeNumber) {
        setFieldAs(NUMBER, employeeNumber);
    }

    public EmployeeNumber getEmployeeNumber() {
        return getFieldAs(NUMBER, EmployeeNumber.class);
    }

    public void setDateOfHire(Date dateOfHire) {
        setFieldAs(DATEOFHIRE, dateOfHire);
    }

    public Date getDateOfHire() {
        return getFieldAs(DATEOFHIRE, Date.class);
    }

    public void setNameOfSpouse(Name spouse) {
        setFieldAs(NAMEOFSPOUSE, spouse);
    }

    public Name getNameOfSpouse() {
        return getFieldAs(NAMEOFSPOUSE, Name.class);
    }

    public void setChildren(Children children) {
        setFieldAs(CHILDREN, children);
    }

    public Children getChildren() {
        return getFieldAs(CHILDREN, Children.class);
    }

    public static class Children extends Asn1SequenceOf<ChildInformation> {
        public Children(ChildInformation ... children) {
            super();
            for (ChildInformation child : children) {
                addElement(child);
            }
        }

        public Children() {
            super();
        }
    }

    public static class ChildInformation extends Asn1SetType {
        private static int NAME = 0;
        private static int DATEOFBIRTH = 1;

        static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
                new Asn1FieldInfo(NAME, -1, Name.class),
                new Asn1FieldInfo(DATEOFBIRTH, 0, Date.class)
        };

        public ChildInformation() {
            super(tags);
        }

        public void setName(Name name) {
            setFieldAs(NAME, name);
        }

        public Name getName() {
            return getFieldAs(NAME, Name.class);
        }

        public void setDateOfBirth(Date date) {
            setFieldAs(DATEOFBIRTH, date);
        }

        public Date getDateOfBirth() {
            return getFieldAs(DATEOFBIRTH, Date.class);
        }
    }

    public static class Name extends TaggingSequence {
        private static int GIVENNAME = 0;
        private static int INITIAL = 1;
        private static int FAMILYNAME = 2;

        static Asn1FieldInfo[] tags = new Asn1FieldInfo[] {
                new Asn1FieldInfo(GIVENNAME, -1, Asn1VisibleString.class),
                new Asn1FieldInfo(INITIAL, -1, Asn1VisibleString.class),
                new Asn1FieldInfo(FAMILYNAME, -1, Asn1VisibleString.class)
        };

        public Name() {
            super(1, tags, true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }

        public Name(String givenName, String initial, String familyName) {
            this();
            setGivenName(givenName);
            setInitial(initial);
            setFamilyName(familyName);
        }

        public void setGivenName(String givenName) {
            setFieldAs(GIVENNAME, new Asn1VisibleString(givenName));
        }

        public String getGivenName() {
            return getFieldAsString(GIVENNAME);
        }

        public void setInitial(String initial) {
            setFieldAs(INITIAL, new Asn1VisibleString(initial));
        }

        public String getInitial() {
            return getFieldAsString(INITIAL);
        }

        public void setFamilyName(String familyName) {
            setFieldAs(FAMILYNAME, new Asn1VisibleString(familyName));
        }

        public String getFamilyName() {
            return getFieldAsString(FAMILYNAME);
        }
    }

    public static class EmployeeNumber extends Asn1Tagging<Asn1Integer> {
        public EmployeeNumber(Integer value) {
            super(2, new Asn1Integer(value), true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public EmployeeNumber() {
            this(null);
        }
    }

    public static class Date extends Asn1Tagging<Asn1VisibleString> {
        public Date(String value) {
            super(3, new Asn1VisibleString(value), true);
            setEncodingOption(EncodingOption.IMPLICIT);
        }
        public Date() {
            this(null);
        }
    }
}