CREATE CONSTRAINT cpe if NOT exists ON (cpe:CPE) ASSERT cpe.uri IS UNIQUE;

CREATE CONSTRAINT cve if NOT exists ON (cve:CVE) ASSERT cve.Name IS UNIQUE;

CREATE CONSTRAINT cwe if NOT exists ON (cwe:CWE) ASSERT cwe.Name IS UNIQUE;

CREATE CONSTRAINT reference if NOT exists ON (ref:Reference_Data) ASSERT ref.url IS UNIQUE;

CREATE CONSTRAINT cvss3 if NOT exists ON (cvss3:CVSS_3) ASSERT cvss3.Name IS UNIQUE;

CREATE CONSTRAINT cvss2 if NOT exists ON (cvss2:CVSS_2) ASSERT cvss2.Name IS UNIQUE;

CREATE CONSTRAINT externalReferencecwe if NOT exists ON (ref:External_Reference_CWE) ASSERT ref.Reference_ID IS UNIQUE;

CREATE CONSTRAINT Consequence if NOT exists ON (con:Consequence) ASSERT con.Scope IS UNIQUE;

CREATE CONSTRAINT Mitigation if NOT exists ON (mit:Mitigation) ASSERT mit.Description IS UNIQUE;

CREATE CONSTRAINT DetectionMethod if NOT exists ON (dec:Detection_Method) ASSERT dec.Method IS UNIQUE;

CREATE CONSTRAINT capec if NOT exists ON (cp:CAPEC) ASSERT cp.Name IS UNIQUE;

CREATE CONSTRAINT cweview if NOT exists ON (v:CWE_VIEW) ASSERT v.ViewID IS UNIQUE;

CREATE CONSTRAINT stakeholder if NOT exists ON (s:Stakeholder) ASSERT s.Type IS UNIQUE;

CREATE INDEX AppPlatformType if NOT exists FOR (n:Applicable_Platform) ON (n.Type);

CREATE CONSTRAINT externalReferencecapec if NOT exists ON (ref:External_Reference_CAPEC) ASSERT ref.Reference_ID IS UNIQUE;

CREATE CONSTRAINT capecview if NOT exists ON (v:CAPEC_VIEW) ASSERT v.ViewID IS UNIQUE;

