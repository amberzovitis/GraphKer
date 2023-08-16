// ------------------------------------------------------------------------
// Insert Categories for CWEs
UNWIND [cweCategoryFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS category RETURN category',
  '
    MERGE (c:CWE {
      Name: "CWE-" + category.ID
    })
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
    FOREACH (member IN category.Relationships.Has_Member |
      MERGE (MemberWeak:CWE {Name: "CWE-" + member.CWE_ID})
      MERGE (c)-[:hasMember {ViewID: member.View_ID}]->(MemberWeak)
    )

    // ------------------------------------------------------------------------
    // Insert Public References for each Category
    WITH c, category
    FOREACH (categoryExReference IN category.References.Reference |
      MERGE (catRef:External_Reference_CWE {Reference_ID: categoryExReference.External_Reference_ID})
      MERGE (c)-[:hasExternal_Reference]->(catRef)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;