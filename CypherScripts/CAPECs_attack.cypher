// Insert CAPECs
UNWIND [capecAttackFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS capec RETURN capec',
  '
    // Insert Attack Patterns for CAPECs
    MERGE (cp:CAPEC {
      Name: "CAPEC-" + capec.ID
    })
      SET cp.ExtendedName = capec.Name,
      cp.Abstraction = capec.Abstraction,
      cp.Status = capec.Status,
      cp.Description = apoc.convert.toString(capec.Description),
      cp.Likelihood_Of_Attack = capec.Likelihood_Of_Attack,
      cp.Typical_Severity = capec.Typical_Severity,
      cp.Alternate_Terms = [value IN capec.Alternate_Terms.Alternate_Term | value.Term],
      cp.Prerequisites = [value IN capec.Prerequisites.Prerequisite | apoc.convert.toString(value)],
      cp.Skills_Required = [value IN capec.Skills_Required.Skill | value.Level],
      cp.Skills_Required_Description = [value IN capec.Skills_Required.Skill | coalesce(apoc.convert.toString(value.text), " NOT SET ")],
      cp.Mitigations = [value IN capec.Mitigations.Mitigation | apoc.convert.toString(value)],
      cp.Examples = [value IN capec.Example_Instances.Example | apoc.convert.toString(value)],
      cp.Notes = [value IN capec.Notes.Note | apoc.convert.toString(value)],
      cp.Submission_Date = capec.Content_History.Submission.Submission_Date,
      cp.Submission_Name = capec.Content_History.Submission.Submission_Name,
      cp.Submission_Organization = capec.Content_History.Submission.Submission_Organization,
      cp.Modifications = [value IN capec.Content_History.Modification | apoc.convert.toString(value)],
      cp.Resources_Required = [value IN capec.Resources_Required.Resource | apoc.convert.toString(value)],
      cp.Indicators = [value IN capec.Indicators.Indicator | apoc.convert.toString(value)]

    // Consequences
    FOREACH (consequence IN capec.Consequences.Consequence |
      MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
      MERGE (cp)-[rel:hasConsequence]->(con)
      ON CREATE SET rel.Impact = [value IN consequence.Impact | value],
      rel.Note = consequence.Note,
      rel.Likelihood = consequence.Likelihood
    )

    // Mitigations
    FOREACH (mit IN capec.Mitigations.Mitigation |
      MERGE (m:Mitigation {
        Description: apoc.convert.toString(mit)
      })
      MERGE (cp)-[:hasMitigation]->(m)
    )

    // Related Attack Patterns
    WITH cp, capec
    FOREACH (Rel_AP IN capec.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (pec:CAPEC { Name: "CAPEC-" + Rel_AP.CAPEC_ID })
      MERGE (cp)-[:RelatedAttackPattern {Nature: Rel_AP.Nature}]->(pec)
    )

    // Public References for CAPECs
    WITH cp, capec
    FOREACH (ExReference IN capec.References.Reference |
      MERGE (Ref:External_Reference_CAPEC {Reference_ID: ExReference.External_Reference_ID})
      MERGE (cp)-[rel:hasExternal_Reference {CAPEC_ID: cp.Name}]->(Ref)
    )
  ',
  {batchSize:1000, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;