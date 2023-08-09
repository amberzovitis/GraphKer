// Insert CVEs - Cypher Script
UNWIND [cveFilesToImport] AS files

CALL apoc.periodic.iterate(
        'CALL apoc.load.json($files) YIELD value AS item RETURN item',
        '
          MERGE (a:CVE {
            Name: item.cve.CVE_data_meta.ID
          })
            ON CREATE  SET a.Assigner = item.cve.CVE_data_meta.ASSIGNER,
            a.Description = [desc IN item.cve.description.description_data WHERE desc.lang = "en" | desc.value],
            a.Published_Date = item.publishedDate,
            a.Last_Modified_Date = item.lastModifiedDate

        // In which CPE is applicable
          FOREACH (node IN item.configurations.nodes |
            FOREACH (child IN node.children |
              FOREACH (cpe_value IN child.cpe_match |
                MERGE (cpe:CPE {
                  uri: cpe_value.cpe23Uri
                })
                MERGE (a)-[:applicableIn {Vulnerable: cpe_value.vulnerable}]->(cpe)
              )
            )
          )

        // To which CWE belongs
          FOREACH (problemtype_data IN item.cve.problemtype.problemtype_data |
            FOREACH (CWE IN problemtype_data.description |
              MERGE (c:CWE {
                Name: CWE.value
              })
                ON CREATE  SET c.Language = CWE.lang
              MERGE (a)-[:Problem_Type]->(c)
            )
          )

        // CVSS3
          MERGE (p:CVSS_3 {
            Name: item.cve.CVE_data_meta.ID + "_CVSS3"
          })
            ON CREATE  SET p.Version = item.impact.baseMetricV3.cvssV3.version, p.Vector_String = item.impact.baseMetricV3.
              cvssV3.vectorString,
            p.Attack_Vector = item.impact.baseMetricV3.cvssV3.attackVector, p.Attack_Complexity = item.impact.baseMetricV3.
              cvssV3.attackComplexity,
            p.Privileges_Required = item.impact.baseMetricV3.cvssV3.privilegesRequired, p.User_Interaction = item.impact.
              baseMetricV3.cvssV3.userInteraction,
            p.Scope = item.impact.baseMetricV3.cvssV3.scope, p.Confidentiality_Impact = item.impact.baseMetricV3.cvssV3.
              confidentialityImpact,
            p.Integrity_Impact = item.impact.baseMetricV3.cvssV3.integrityImpact, p.Availability_Impact = item.impact.
              baseMetricV3.cvssV3.availabilityImpact,
            p.Base_Score = item.impact.baseMetricV3.cvssV3.baseScore, p.Base_Severity = item.impact.baseMetricV3.cvssV3.
              baseSeverity,
            p.Exploitability_Score = item.cve.impact.baseMetricV3.exploitabilityScore,
            p.Impact_Score = item.cve.impact.baseMetricV3.impactScore
          MERGE (a)-[:CVSS3_Impact]->(p)

        // CVSS2
          MERGE (l:CVSS_2 {
            Name: item.cve.CVE_data_meta.ID + "_CVSS2"
          })
            ON CREATE  SET l.Version = item.impact.baseMetricV2.cvssV2.version, l.Vector_String = item.impact.baseMetricV2.
              cvssV2.vectorString,
            l.Access_Vector = item.impact.baseMetricV2.cvssV2.accessVector, l.Access_Complexity = item.impact.baseMetricV2.
              cvssV2.accessComplexity,
            l.Authentication = item.impact.baseMetricV2.cvssV2.authentication,
            l.Confidentiality_Impact = item.impact.baseMetricV2.cvssV2.confidentialityImpact,
            l.Integrity_Impact = item.impact.baseMetricV2.cvssV2.integrityImpact,
            l.Availability_Impact = item.impact.baseMetricV2.cvssV2.availabilityImpact,
            l.Base_Score = item.impact.baseMetricV2.cvssV2.baseScore,
            l.Exploitability_Score = item.cve.impact.baseMetricV2.exploitabilityScore,
            l.Severity = item.cve.impact.baseMetricV2.severity, l.Impact_Score = item.cve.impact.baseMetricV2.impactScore,
            l.acInsufInfo = item.cve.impact.baseMetricV2.acInsufInfo,
            l.Obtain_All_Privileges = item.cve.impact.baseMetricV2.obtainAllPrivileges,
            l.Obtain_User_Privileges = item.cve.impact.baseMetricV2.obtainUserPrivileges,
            l.Obtain_Other_Privileges = item.cve.impact.baseMetricV2.obtainOtherPrivileges,
            l.User_Interaction_Required = item.cve.impact.baseMetricV2.userInteractionRequired
          MERGE (a)-[:CVSS2_Impact]->(l)

        // Public References
          FOREACH (reference_data IN item.cve.references.reference_data |
            MERGE (r:Reference_Data {
              url: reference_data.url
            })
              ON CREATE  SET r.Name = reference_data.name, r.refSource = reference_data.refsource
            MERGE (a)-[:referencedBy]->(r)
          )
        ',
        {batchSize:200, params: {files: files}}
    ) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics