// Insert CAPECs Catalog - Cypher Script

UNWIND [capecReferenceFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS reference RETURN reference',
  '
    // Insert External References for CAPECs
    MERGE (r:External_Reference_CAPEC {Reference_ID: reference.Reference_ID})
      SET r.Author = [value IN reference.Author | value], r.Title = reference.Title,
      r.Edition = reference.Edition, r.URL = reference.URL,
      r.Publication_Year = reference.Publication_Year, r.Publisher = reference.Publisher
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;


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

// ------------------------------------------------------------------------

// ------------------------------------------------------------------------
// Insert Categories for CAPECs
UNWIND [capecCategoryFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS category RETURN category',
  '
    MERGE (c:CAPEC {Name: "CAPEC-" + category.ID})
    SET c.Extended_Name = category.Name,
    c.Status = category.Status,
    c.Summary = apoc.convert.toString(category.Summary),
    c.Notes = apoc.convert.toString(category.Notes),
    c.Submission_Name = category.Content_History.Submission.Submission_Name,
    c.Submission_Date = category.Content_History.Submission.Submission_Date,
    c.Submission_Organization = category.Content_History.Submission.Submission_Organization,
    c.Modification = [value IN category.Content_History.Modification | apoc.convert.toString(value)]

    // Insert Members for each Category
    WITH c, category
    FOREACH (members IN category.Relationships.Has_Member |
      MERGE (MemberAP:CAPEC {Name: "CAPEC-" + members.CAPEC_ID})
      MERGE (c)-[:hasMember]->(MemberAP)
    )

    WITH c, category
    FOREACH (categoryExReference IN category.References.Reference |
      MERGE (catRef:External_Reference_CAPEC {Reference_ID: categoryExReference.External_Reference_ID})
      MERGE (c)-[rel:hasExternal_Reference]->(catRef)
      SET rel.Section = categoryExReference.Section
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;

// ------------------------------------------------------------------------
// Insert Views for CAPECs

UNWIND [capecViewFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS view RETURN view',
  '
    MERGE (v:CAPEC_VIEW {ViewID: view.ID})
      SET v.Name = view.Name, v.Type = view.Type, v.Status = view.Status,
      v.Objective = apoc.convert.toString(view.Objective), v.Filter = view.Filter,
      v.Notes = apoc.convert.toString(view.Notes),
      v.Submission_Name = view.Content_History.Submission.Submission_Name,
      v.Submission_Date = view.Content_History.Submission.Submission_Date,
      v.Submission_Organization = view.Content_History.Submission.Submission_Organization,
      v.Modification = [value IN view.Content_History.Modification | apoc.convert.toString(value)]

      // Insert Stakeholders for each View
      FOREACH (value IN view.Audience.Stakeholder |
        MERGE (st:Stakeholder {Type: value.Type})
        MERGE (v)-[rel:usefulFor]->(st)
        SET rel.Description = value.Description
      )

      // Insert Members for each View
      WITH v, view
      FOREACH (members IN view.Members.Has_Member |
        MERGE (MemberAP:CAPEC {Name: "CAPEC-" + members.CAPEC_ID})
        MERGE (v)-[:hasMember]->(MemberAP)
      )


      // ------------------------------------------------------------------------
      // Insert Public References for each View
      WITH v, view
      FOREACH (viewExReference IN view.References.Reference |
        MERGE (v:CAPEC_VIEW {ViewID: view.ID})
        MERGE (viewRef:External_Reference_CAPEC {Reference_ID: viewExReference.External_Reference_ID})
        MERGE (v)-[:hasExternal_Reference]->(viewRef)
      )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;
