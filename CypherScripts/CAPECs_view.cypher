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
